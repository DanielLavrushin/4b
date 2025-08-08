// mangle/tcp_test.go
package mangle

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// --- helpers -------------------------------------------------------------

func buildRawIPv4TCP(win uint16, payload []byte) []byte {
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{10, 0, 0, 1},
		DstIP:    net.IP{10, 0, 0, 2},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 12345, DstPort: 443,
		Seq: 1000, ACK: true,
		DataOffset: 5,
		Window:     win,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload))
	return buf.Bytes()
}

func decodeTCPv4(raw []byte) (*layers.IPv4, *layers.TCP, []byte) {
	p := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
	ip := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	var app []byte
	if ap := p.ApplicationLayer(); ap != nil {
		app = ap.Payload()
	}
	return ip, tcp, app
}

func decodeTCPAny(raw []byte) (*layers.TCP, []byte, bool) {
	// Try IPv4 first
	if p := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default); p.ErrorLayer() == nil {
		if tl := p.Layer(layers.LayerTypeTCP); tl != nil {
			var app []byte
			if ap := p.ApplicationLayer(); ap != nil {
				app = ap.Payload()
			}
			return tl.(*layers.TCP), app, true
		}
	}
	// Then IPv6
	if p := gopacket.NewPacket(raw, layers.LayerTypeIPv6, gopacket.Default); p.ErrorLayer() == nil {
		if tl := p.Layer(layers.LayerTypeTCP); tl != nil {
			var app []byte
			if ap := p.ApplicationLayer(); ap != nil {
				app = ap.Payload()
			}
			return tl.(*layers.TCP), app, true
		}
	}
	return nil, nil, false
}

/* ---------- IPv6 helpers ---------- */

func buildRawIPv6TCP(win uint16, payload []byte) []byte {
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      net.IP{0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:      net.IP{0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		NextHeader: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort:    23456,
		DstPort:    443,
		Seq:        42,
		ACK:        true,
		DataOffset: 5,
		Window:     win,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload))
	return buf.Bytes()
}

func decodeTCPv6(raw []byte) (*layers.IPv6, *layers.TCP, []byte) {
	p := gopacket.NewPacket(raw, layers.LayerTypeIPv6, gopacket.Default)
	ip := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	tcp := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	var app []byte
	if ap := p.ApplicationLayer(); ap != nil {
		app = ap.Payload()
	}
	return ip, tcp, app
}

// --- helper: IPv6 + Hop-by-Hop ext, then TCP (forces fallback) ----------
func buildRawIPv6HBHThenTCP(win uint16, payload []byte) []byte {
	// IPv6 base header (40 bytes)
	h := make([]byte, 40)
	h[0] = 0x60 // version 6
	h[6] = 0    // NextHeader = Hop-by-Hop (0) -> skips fast path
	h[7] = 64   // HopLimit
	copy(h[8:24], net.ParseIP("2001::1").To16())
	copy(h[24:40], net.ParseIP("2001::2").To16())

	// HBH extension header: 8 bytes total (Hdr Ext Len = 0)
	hbh := make([]byte, 8)
	hbh[0] = 6 // NextHeader = TCP
	hbh[1] = 0 // Hdr Ext Len (in 8-byte units, not incl. first 8 bytes)

	// Minimal TCP header (20) + payload; we set Window, leave checksum junk (we won't reach TCP in parser)
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[14:16], win) // Window
	copy(tcp[20:], payload)

	// Set payload length in IPv6 header
	pl := len(hbh) + len(tcp)
	h[4] = byte(pl >> 8)
	h[5] = byte(pl)

	return append(append(h, hbh...), tcp...)
}

// Build IPv6 with a Destination Options header (NextHeader=60) then TCP.
// TCP checksum is correct so gopacket can decode it.
func buildRawIPv6DestOptThenTCP(win uint16, payload []byte) []byte {
	v6 := make([]byte, 40)
	v6[0] = 0x60 // IPv6
	v6[6] = 60   // NextHeader = Destination Options
	v6[7] = 64   // HopLimit
	copy(v6[8:24], net.ParseIP("2001::1").To16())
	copy(v6[24:40], net.ParseIP("2001::2").To16())

	// 8-byte Destination Options, points to TCP next
	dest := make([]byte, 8)
	dest[0] = 6 // NextHeader = TCP
	dest[1] = 0 // Hdr Ext Len = 0 -> 8 bytes total

	// Minimal TCP header + payload
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], 12345) // src
	binary.BigEndian.PutUint16(tcp[2:4], 443)   // dst
	tcp[12] = 5 << 4                            // data offset=5 (20 bytes)
	binary.BigEndian.PutUint16(tcp[14:16], win) // window
	// zero checksum, then compute
	tcp[16], tcp[17] = 0, 0
	copy(tcp[20:], payload)

	upperLen := uint32(len(tcp))
	pseudo := make([]byte, 40)
	copy(pseudo[0:16], v6[8:24])
	copy(pseudo[16:32], v6[24:40])
	pseudo[32] = byte(upperLen >> 24)
	pseudo[33] = byte(upperLen >> 16)
	pseudo[34] = byte(upperLen >> 8)
	pseudo[35] = byte(upperLen)
	pseudo[39] = 6 // TCP
	s := sum16(pseudo) + sum16(tcp)
	csum := finalize(s)
	tcp[16] = byte(csum >> 8)
	tcp[17] = byte(csum)

	// IPv6 payload length = dest opts + tcp
	pl := len(dest) + len(tcp)
	v6[4] = byte(pl >> 8)
	v6[5] = byte(pl)

	return append(append(v6, dest...), tcp...)
}

// --- tests ---------------------------------------------------------------

func TestSendAlteredSyn_WindowOverride(t *testing.T) {
	// capture the single send
	var sent [][]byte
	origSend := sendRaw
	sendRaw = func(b []byte) error { sent = append(sent, b); return nil }
	t.Cleanup(func() { sendRaw = origSend })

	sec := &config.Section{
		SynFake:   true,
		FKWinSize: 4096,
		// choose any non-empty payload for SYN fake
		FakeSNIPkt: []byte("hello"),
	}

	ip4 := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{1, 1, 1, 1}, DstIP: net.IP{2, 2, 2, 2}}
	tcp := &layers.TCP{SrcPort: 10000, DstPort: 443, SYN: true, DataOffset: 5, Window: 123}

	verdict := sendAlteredSyn(tcp, ip4, nil, sec)
	if verdict != VerdictDrop {
		t.Fatalf("verdict=%v want Drop", verdict)
	}
	if len(sent) != 1 {
		t.Fatalf("sent=%d packets, want 1", len(sent))
	}
	_, tt, _ := decodeTCPv4(sent[0])
	if tt.Window != 4096 {
		t.Fatalf("tcp.window=%d want 4096", tt.Window)
	}
}

func TestProcessTCP_WindowOverrideOnForgedSegments(t *testing.T) {
	// stub raw sender & SNI extractor
	var sent [][]byte
	origSend := sendRaw
	sendRaw = func(b []byte) error { sent = append(sent, b); return nil }
	t.Cleanup(func() { sendRaw = origSend })

	origExtract := extractSNI
	extractSNI = func(_ []byte) ([]byte, error) { return []byte("example.com"), nil }
	t.Cleanup(func() { extractSNI = origExtract })

	sec := &config.Section{
		// ensure we actually do TLS split path
		TLSEnabled:            true,
		FKWinSize:             2048,
		SNIDomains:            []string{"example.com"},
		FragmentationStrategy: config.FragStratNone,
		Seg2Delay:             0,
		FakeSNI:               false,
		FakeSNISeqLen:         0,
		FakingStrategy:        0,
	}

	ip4 := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{10, 0, 0, 3}, DstIP: net.IP{10, 0, 0, 4}}
	tcp := &layers.TCP{
		SrcPort: 1111, DstPort: 443,
		Seq: 5000, ACK: true,
		DataOffset: 5,
		Window:     100,
	}

	// include SNI in payload so split point is stable
	payload := gopacket.Payload([]byte("XXXXexample.comYYYY"))

	v := processTCP(tcp, ip4, nil, payload, sec, nil)
	if v != VerdictDrop {
		t.Fatalf("verdict=%v want Drop", v)
	}
	if len(sent) != 2 {
		t.Fatalf("sent %d packets, want 2 (first/second forged)", len(sent))
	}
	for i, b := range sent {
		_, tt, _ := decodeTCPv4(b)
		if tt.Window != 2048 {
			t.Fatalf("pkt[%d] tcp.window=%d want 2048", i, tt.Window)
		}
	}
}

func TestSendFrags_OverridesTCPWindow(t *testing.T) {
	var sent [][]byte
	origSend := sendRaw
	sendRaw = func(b []byte) error { sent = append(sent, b); return nil }
	t.Cleanup(func() { sendRaw = origSend })

	// stub fake sequence to avoid touching nil headers
	origFake := sendFakeSeq
	sendFakeSeq = func(_ fakeType, _ *layers.TCP, _ *layers.IPv4, _ *layers.IPv6) {}
	t.Cleanup(func() { sendFakeSeq = origFake })

	sec := &config.Section{
		FKWinSize:      7777,
		Seg2Delay:      0,
		FragSNIReverse: false,
		// ensure no other fakes are triggered
		FakingStrategy: 0,
		FakeSNI:        false,
	}

	a := buildRawIPv4TCP(1000, []byte("AAA"))
	b := buildRawIPv4TCP(2000, []byte("BBB"))

	// dvs=0 is fine for this test, tcp/ip are irrelevant
	sendFrags(sec, a, b, 0, nil, nil, nil)

	if len(sent) != 2 {
		t.Fatalf("sent %d packets, want 2", len(sent))
	}
	for i, pkt := range sent {
		_, tt, _ := decodeTCPv4(pkt)
		if tt.Window != 7777 {
			t.Fatalf("pkt[%d] tcp.window=%d want 7777", i, tt.Window)
		}
	}
}

func TestSendFrags_Seg2Delay_XorRule(t *testing.T) {
	var calls []string
	origRaw, origDel := sendRaw, sendDelayed
	sendRaw = func(_ []byte) error { calls = append(calls, "raw"); return nil }
	sendDelayed = func(_ []byte, _ uint) error { calls = append(calls, "delay"); return nil }
	t.Cleanup(func() { sendRaw, sendDelayed = origRaw, origDel })

	sec := &config.Section{Seg2Delay: 123, FragSNIReverse: false}
	a, b := []byte{0}, []byte{1}

	// dvs==0 -> XOR false -> no delay
	calls = nil
	sendFrags(sec, a, b, 0, nil, nil, nil)
	if len(calls) != 2 || calls[1] != "raw" {
		t.Fatalf("want raw second when dvs==0, got %v", calls)
	}

	// dvs>0 -> XOR true -> delay
	calls = nil
	sendFrags(sec, a, b, 10, nil, nil, nil)
	if len(calls) != 2 || calls[1] != "delay" {
		t.Fatalf("want delay second when dvs>0, got %v", calls)
	}

	// reversed flips result: dvs>0 but reversed -> no delay
	sec.FragSNIReverse = true
	calls = nil
	sendFrags(sec, a, b, 10, nil, nil, nil)
	if len(calls) != 2 || calls[1] != "raw" {
		t.Fatalf("want raw second when reversed, got %v", calls)
	}
}

func TestProcessTCP_NonFrag_Seg2Delay_XorRule(t *testing.T) {
	// record call sequence: "raw", "fake", "delay"
	var calls []string

	origRaw, origDel, origFake := sendRaw, sendDelayed, sendFakeSeq
	sendRaw = func(_ []byte) error { calls = append(calls, "raw"); return nil }
	sendDelayed = func(_ []byte, _ uint) error { calls = append(calls, "delay"); return nil }
	sendFakeSeq = func(_ fakeType, _ *layers.TCP, _ *layers.IPv4, _ *layers.IPv6) {
		calls = append(calls, "fake")
	}
	t.Cleanup(func() {
		sendRaw, sendDelayed, sendFakeSeq = origRaw, origDel, origFake
	})

	// force SNI "example.com" regardless of payload contents (parse mode)
	origExtract := extractSNI
	extractSNI = func(_ []byte) ([]byte, error) { return []byte("example.com"), nil }
	t.Cleanup(func() { extractSNI = origExtract })

	sec := &config.Section{
		TLSEnabled:            true,
		SNIDetection:          0, // parse
		SNIDomains:            []string{"example.com"},
		FragmentationStrategy: config.FragStratNone,
		Seg2Delay:             100,
		FragSNIReverse:        false,
	}

	// VALID IPv4 header (needed so gopacket can serialize forged segments)
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{1, 1, 1, 1},
		DstIP:    net.IP{2, 2, 2, 2},
	}
	tcp := &layers.TCP{
		SrcPort:    1111,
		DstPort:    443,
		Seq:        1,
		ACK:        true,
		DataOffset: 5,
		Window:     100,
	}

	// Case 1: dvsLocal==0  (SNI at offset 0) -> raw, fake, raw
	calls = nil
	v := processTCP(tcp, ip4, nil, gopacket.Payload([]byte("example.com-TAIL")), sec, nil)
	if v != VerdictDrop {
		t.Fatalf("want Drop, got %v", v)
	}
	if got, want := strings.Join(calls, ","), "raw,fake,raw"; got != want {
		t.Fatalf("calls=%s want %s", got, want)
	}

	// Case 2: dvsLocal>0 (SNI after 2 bytes) -> raw, fake, delay
	calls = nil
	v = processTCP(tcp, ip4, nil, gopacket.Payload([]byte("XXexample.comYY")), sec, nil)
	if v != VerdictDrop {
		t.Fatalf("want Drop, got %v", v)
	}
	if got, want := strings.Join(calls, ","), "raw,fake,delay"; got != want {
		t.Fatalf("calls=%s want %s", got, want)
	}

	// Case 3: reversed flips XOR -> raw, fake, raw (even though dvsLocal>0)
	sec.FragSNIReverse = true
	calls = nil
	v = processTCP(tcp, ip4, nil, gopacket.Payload([]byte("XXexample.comYY")), sec, nil)
	if v != VerdictDrop {
		t.Fatalf("want Drop, got %v", v)
	}
	if got, want := strings.Join(calls, ","), "raw,fake,raw"; got != want {
		t.Fatalf("calls=%s want %s", got, want)
	}
}

// 1) IPv6 fallback path in overrideTCPWindow (no fast path for v6)
func TestOverrideTCPWindow_IPv6_FallbackSetsWindow(t *testing.T) {
	raw := buildRawIPv6TCP(1000, []byte("v6payload"))
	out, ok := overrideTCPWindow(raw, 7777)
	if !ok {
		t.Fatalf("overrideTCPWindow(v6) returned ok=false")
	}
	_, tt, _ := decodeTCPv6(out)
	if tt.Window != 7777 {
		t.Fatalf("tcp.window=%d want 7777", tt.Window)
	}
}

// 2) SYN-fake over IPv6 must override window
func TestSendAlteredSyn_IPv6_WindowOverride(t *testing.T) {
	var sent [][]byte
	origSend := sendRaw
	sendRaw = func(b []byte) error { sent = append(sent, b); return nil }
	t.Cleanup(func() { sendRaw = origSend })

	sec := &config.Section{
		SynFake:    true,
		FKWinSize:  6000,
		FakeSNIPkt: []byte("hi"),
	}

	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      net.IP{0x20, 0x01, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:      net.IP{0x20, 0x01, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2},
		NextHeader: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{SrcPort: 10000, DstPort: 443, SYN: true, DataOffset: 5, Window: 123}

	verdict := sendAlteredSyn(tcp, nil, ip6, sec)
	if verdict != VerdictDrop {
		t.Fatalf("verdict=%v want Drop", verdict)
	}
	if len(sent) != 1 {
		t.Fatalf("sent=%d packets, want 1", len(sent))
	}
	_, tt, _ := decodeTCPv6(sent[0])
	if tt.Window != 6000 {
		t.Fatalf("tcp.window=%d want 6000", tt.Window)
	}
}

// 3) Non-frag IPv6 split + XOR delay rule + fake in the middle
func TestProcessTCP_IPv6_NonFrag_Seg2Delay_XorRule(t *testing.T) {
	var calls []string

	origRaw, origDel, origFake := sendRaw, sendDelayed, sendFakeSeq
	sendRaw = func(_ []byte) error { calls = append(calls, "raw"); return nil }
	sendDelayed = func(_ []byte, _ uint) error { calls = append(calls, "delay"); return nil }
	sendFakeSeq = func(_ fakeType, _ *layers.TCP, _ *layers.IPv4, _ *layers.IPv6) {
		calls = append(calls, "fake")
	}
	t.Cleanup(func() { sendRaw, sendDelayed, sendFakeSeq = origRaw, origDel, origFake })

	origExtract := extractSNI
	extractSNI = func(_ []byte) ([]byte, error) { return []byte("example.com"), nil }
	t.Cleanup(func() { extractSNI = origExtract })

	sec := &config.Section{
		TLSEnabled:            true,
		SNIDetection:          0,
		SNIDomains:            []string{"example.com"},
		FragmentationStrategy: config.FragStratNone,
		Seg2Delay:             77,
		FragSNIReverse:        false,
	}

	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      net.IP{0x20, 0x01, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:      net.IP{0x20, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2},
		NextHeader: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort:    1111,
		DstPort:    443,
		Seq:        1,
		ACK:        true,
		DataOffset: 5,
		Window:     100,
	}

	// dvsLocal==0 → raw, fake, raw
	calls = nil
	v := processTCP(tcp, nil, ip6, gopacket.Payload([]byte("example.com-TAIL")), sec, nil)
	if v != VerdictDrop {
		t.Fatalf("want Drop, got %v", v)
	}
	if got := strings.Join(calls, ","); got != "raw,fake,raw" {
		t.Fatalf("calls=%s want raw,fake,raw", got)
	}

	// dvsLocal>0 → raw, fake, delay
	calls = nil
	v = processTCP(tcp, nil, ip6, gopacket.Payload([]byte("XXexample.comYY")), sec, nil)
	if v != VerdictDrop {
		t.Fatalf("want Drop, got %v", v)
	}
	if got := strings.Join(calls, ","); got != "raw,fake,delay" {
		t.Fatalf("calls=%s want raw,fake,delay", got)
	}

	// reversed flips XOR → raw, fake, raw
	sec.FragSNIReverse = true
	calls = nil
	v = processTCP(tcp, nil, ip6, gopacket.Payload([]byte("XXexample.comYY")), sec, nil)
	if v != VerdictDrop {
		t.Fatalf("want Drop, got %v", v)
	}
	if got := strings.Join(calls, ","); got != "raw,fake,raw" {
		t.Fatalf("calls=%s want raw,fake,raw", got)
	}
}

// 4) IP-frag path (IPv4) + TCP-frag path (IPv6) smoke via stubs
func TestProcessTCP_FragPaths_CallersAndSendOrder(t *testing.T) {
	// Stub fragger to control outputs
	origIP4, origTCP := ip4FragFn, tcpFragFn
	ip4FragFn = func(_ []byte, _ int) ([]byte, []byte, error) {
		return buildRawIPv4TCP(100, []byte("A")), buildRawIPv4TCP(100, []byte("B")), nil
	}
	tcpFragFn = func(_ []byte, _ int) ([]byte, []byte, error) {
		// Return v6 raws so we exercise overrideTCPWindow fallback path (but FKWinSize=0)
		return buildRawIPv6TCP(100, []byte("C")), buildRawIPv6TCP(100, []byte("D")), nil
	}
	t.Cleanup(func() { ip4FragFn, tcpFragFn = origIP4, origTCP })

	label := func(b []byte) string {
		if _, app, ok := decodeTCPAny(b); ok && len(app) > 0 {
			return string(app[0])
		}
		return "?"
	}

	// Stub senders to record order; stub fake in the middle
	var calls []string
	origRaw, origDel, origFake := sendRaw, sendDelayed, sendFakeSeq
	sendRaw = func(b []byte) error {
		calls = append(calls, "raw:"+label(b))
		return nil
	}
	sendDelayed = func(b []byte, _ uint) error {
		calls = append(calls, "delay:"+label(b))
		return nil
	}
	sendFakeSeq = func(_ fakeType, _ *layers.TCP, _ *layers.IPv4, _ *layers.IPv6) {
		calls = append(calls, "fake")
	}
	t.Cleanup(func() { sendRaw, sendDelayed, sendFakeSeq = origRaw, origDel, origFake })

	// Common sec (no window override to keep frag outputs intact)
	sec := &config.Section{
		TLSEnabled:            true,
		FragmentationStrategy: config.FragStratIP, // will set per-case
		SNIDomains:            []string{"example.com"},
		FragSNIFaked:          true, // so we get the middle fake
		Seg2Delay:             50,
		FragSNIReverse:        false,
		FKWinSize:             0,
	}

	// Force parser to find SNI
	origExtract := extractSNI
	extractSNI = func(_ []byte) ([]byte, error) { return []byte("example.com"), nil }
	t.Cleanup(func() { extractSNI = origExtract })

	// IPv4 IP-frag case
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{1, 1, 1, 1}, DstIP: net.IP{2, 2, 2, 2},
	}
	tcp := &layers.TCP{SrcPort: 1111, DstPort: 443, Seq: 1, ACK: true, DataOffset: 5, Window: 100}

	calls = nil
	sec.FragmentationStrategy = config.FragStratIP
	v := processTCP(tcp, ip4, nil, gopacket.Payload([]byte("XXexample.comYY")), sec, buildRawIPv4TCP(100, []byte("XXexample.comYY")))
	if v != VerdictDrop {
		t.Fatalf("IP-frag want Drop, got %v", v)
	}
	// Expect: first(A), fake, then second(B) with XOR delay (dvs>0, not reversed) → delay:B
	want := "raw:A,fake,delay:B"
	if got := strings.Join(calls, ","); got != want {
		t.Fatalf("IP-frag calls=%s want %s", got, want)
	}

	// IPv6 TCP-frag case (uses stubbed tcpFragFn)
	ip6 := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP,
		SrcIP: net.IP{0x20, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP: net.IP{0x20, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2},
	}
	calls = nil
	sec.FragmentationStrategy = config.FragStratTCP
	v = processTCP(tcp, nil, ip6, gopacket.Payload([]byte("XXexample.comYY")), sec, buildRawIPv6TCP(100, []byte("XXexample.comYY")))
	if v != VerdictDrop {
		t.Fatalf("TCP-frag want Drop, got %v", v)
	}
	// tcpFragFn stub returns "C" then "D"
	want = "raw:C,fake,delay:D"
	if got := strings.Join(calls, ","); got != want {
		t.Fatalf("TCP-frag calls=%s want %s", got, want)
	}
}

func TestOverrideTCPWindow_IPv6_FallbackNoChange(t *testing.T) {
	raw := buildRawIPv6HBHThenTCP(1234, []byte("Z"))
	out, ok := overrideTCPWindow(raw, 7777)
	if ok {
		t.Fatalf("expected ok=false (fallback couldn’t reach TCP through ext hdrs)")
	}
	if !bytes.Equal(out, raw) {
		t.Fatalf("expected packet unchanged on fallback; got mutated")
	}
}

func TestOverrideTCPWindow_IPv6_FallbackWithExtSetsWindow(t *testing.T) {
	inWin := uint16(1111)
	outWin := uint16(7777)
	payload := []byte("PAY")

	raw := buildRawIPv6DestOptThenTCP(inWin, payload)
	out, ok := overrideTCPWindow(raw, outWin)
	if !ok {
		t.Fatalf("expected fallback to apply (ok=true)")
	}

	// After fallback re-serialize, extension header may be dropped by gopacket;
	// so TCP could start at 40 (no ext) or 48 (ext kept).
	tryOffsets := []int{40, 48}

	var found bool
	for _, tcpStart := range tryOffsets {
		if len(out) < tcpStart+20 {
			continue
		}
		gotWin := binary.BigEndian.Uint16(out[tcpStart+14 : tcpStart+16])
		if gotWin != outWin {
			continue
		}
		// payload should be intact
		if len(out) >= tcpStart+20+len(payload) &&
			bytes.Equal(out[tcpStart+20:tcpStart+20+len(payload)], payload) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("did not find TCP window=%d with intact payload at expected offsets", outWin)
	}
}
