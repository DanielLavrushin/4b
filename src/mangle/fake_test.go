package mangle

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/* ---------- helpers ---------- */

// decode uses gopacket to pull IPv4/IPv6 and TCP layers back out so we can
// inspect their fields.
func decode(raw []byte) (ip4 *layers.IPv4, ip6 *layers.IPv6, tcp *layers.TCP) {
	// ---- first pass: IPv4 root -----------------------------------------
	p := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
	if l := p.Layer(layers.LayerTypeIPv4); l != nil {
		ip4 = l.(*layers.IPv4)
	}
	if l := p.Layer(layers.LayerTypeTCP); l != nil {
		tcp = l.(*layers.TCP)
	}

	// ---- fall back to IPv6 ---------------------------------------------
	if ip4 == nil && tcp == nil { // nothing decoded → maybe v6
		p = gopacket.NewPacket(raw, layers.LayerTypeIPv6, gopacket.Default)
		if l := p.Layer(layers.LayerTypeIPv6); l != nil {
			ip6 = l.(*layers.IPv6)
		}
		if l := p.Layer(layers.LayerTypeTCP); l != nil {
			tcp = l.(*layers.TCP)
		}
	}
	return
}

// template constructs a minimal IP+TCP template used in all tests.
func templateIPv4() (*layers.IPv4, *layers.TCP) {
	ip := &layers.IPv4{
		SrcIP:    net.IP{1, 1, 1, 1},
		DstIP:    net.IP{2, 2, 2, 2},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 1234,
		DstPort: 80,
		Seq:     1000,
		Window:  65535,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	return ip, tcp
}

func templateIPv6() (*layers.IPv6, *layers.TCP) {
	ip6 := &layers.IPv6{
		SrcIP:      net.IP(bytes.Repeat([]byte{0x11}, 16)),
		DstIP:      net.IP(bytes.Repeat([]byte{0x22}, 16)),
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 2222,
		DstPort: 443,
		Seq:     9000,
		Window:  65535,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip6)
	return ip6, tcp
}

// --- Inline fake is plain (no strategy effects) -----------------------------

func makeClientHelloWithSNI(host string) []byte {
	h := []byte(host)
	hostLen := len(h)

	// SNI extension
	// ext type 0x0000, ext data:
	//   server_name_list_len(2) = 1 + 2 + hostLen
	//   name_type(1)=0
	//   host_name_len(2)=hostLen
	//   host_name(hostLen)
	snListLen := 1 + 2 + hostLen
	extDataLen := 2 + snListLen

	ext := make([]byte, 0, 4+extDataLen)
	ext = append(ext, 0x00, 0x00)                            // type
	ext = append(ext, byte(extDataLen>>8), byte(extDataLen)) // length
	ext = append(ext, byte(snListLen>>8), byte(snListLen))   // server_name_list len
	ext = append(ext, 0x00)                                  // name_type = host_name(0)
	ext = append(ext, byte(hostLen>>8), byte(hostLen))       // host len
	ext = append(ext, h...)                                  // host

	// Extensions block (only SNI)
	extsLen := len(ext)
	exts := make([]byte, 0, 2+extsLen)
	exts = append(exts, byte(extsLen>>8), byte(extsLen))
	exts = append(exts, ext...)

	// Minimal ClientHello body (TLS 1.2 style)
	body := make([]byte, 0, 2+32+1+2+2+1+1+len(exts))
	body = append(body, 0x03, 0x03)             // client_version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session_id_len = 0
	body = append(body, 0x00, 0x02, 0x00, 0x2f) // cipher_suites_len=2, one suite 0x002f
	body = append(body, 0x01, 0x00)             // compression_methods_len=1, null(0)
	body = append(body, exts...)                // extensions

	// Handshake header (type=ClientHello(1), len=bodyLen)
	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, 0x01) // ClientHello
	bodyLen := len(body)
	hs = append(hs, 0x00, byte(bodyLen>>8), byte(bodyLen)) // 3-byte length
	hs = append(hs, body...)

	// TLS record: type=handshake(22), ver=0x0303, len=hsLen
	rec := make([]byte, 0, 5+len(hs))
	rec = append(rec, 0x16, 0x03, 0x03) // record type + version
	hsLen := len(hs)
	rec = append(rec, byte(hsLen>>8), byte(hsLen)) // record length
	rec = append(rec, hs...)
	return rec
}

/* ---------- tests for iterateStrategies ---------- */

func TestIterateStrategies(t *testing.T) {
	ft := fakeType{Strategy: fakeStratRandSeq | fakeStratTTL | fakeStratTCPCheck}
	var got []int
	ft.iterateStrategies(func(flag int) { got = append(got, flag) })

	want := []int{fakeStratRandSeq, fakeStratTTL, fakeStratTCPCheck}
	if len(got) != len(want) {
		t.Fatalf("iterateStrategies: want %v got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("iterateStrategies order mismatch: want %v got %v", want, got)
		}
	}
}

/* ---------- init ---------- */

func init() {
	// ensure deterministic RandSeq test
	rand.Seed(time.Now().UnixNano())
}

/* ---------- tests for buildFake ---------- */

func TestBuildFake_RandSeqAndTTL_IPv4(t *testing.T) {
	rand.Seed(42)
	ip, tcpTmpl := templateIPv4()

	ft := fakeType{
		RandSeqOff: 500,
		TTL:        10,
		Payload:    []byte("abc"),
	}
	raw, err := buildFake(tcpTmpl, ip, nil, ft.Payload, fakeStratRandSeq|fakeStratTTL, tcpTmpl.Seq, ft)
	if err != nil {
		t.Fatalf("buildFake: %v", err)
	}

	ip4, _, tcp := decode(raw)
	if ip4 == nil || tcp == nil {
		t.Fatalf("decode failed")
	}
	if tcp.Seq < tcpTmpl.Seq || tcp.Seq > tcpTmpl.Seq+uint32(ft.RandSeqOff) {
		t.Fatalf("RandSeq out of range: got %d", tcp.Seq)
	}
	if ip4.TTL != ft.TTL {
		t.Fatalf("TTL not applied: got %d want %d", ip4.TTL, ft.TTL)
	}
}

func TestBuildFake_PastSeq_IPv6(t *testing.T) {
	ip6, tcpTmpl := templateIPv6()

	ft := fakeType{
		RandSeqOff: 200,
		Payload:    []byte("xyz"),
	}
	raw, err := buildFake(tcpTmpl, nil, ip6, ft.Payload,
		fakeStratPastSeq, tcpTmpl.Seq, ft)
	if err != nil {
		t.Fatalf("buildFake: %v", err)
	}

	// IPv6 header is a fixed 40 bytes; sequence number is the second
	// 32-bit field in the TCP header (offset 4).
	if len(raw) < 48 {
		t.Fatalf("packet too short")
	}
	seq := binary.BigEndian.Uint32(raw[44:48])
	want := tcpTmpl.Seq - uint32(ft.RandSeqOff)
	if seq != want {
		t.Fatalf("PastSeq wrong: got %d want %d", seq, want)
	}
}

/* ---------- test for fakeTypeFromSection ---------- */

func TestFakeTypeFromSection(t *testing.T) {
	sec := &config.Section{
		FakeSNISeqLen:  3,
		FakingStrategy: config.FakeStratTTL | config.FakeStratRandSeq,
		FakeSeqOffset:  55,
		FakingTTL:      9,
		FakeSNIPkt:     []byte("data"),
		Seg2Delay:      123,
	}

	ft := fakeTypeFromSection(sec)
	if ft.SequenceLen != 3 || ft.Strategy != sec.FakingStrategy ||
		ft.RandSeqOff != 55 || ft.TTL != 9 || !bytes.Equal(ft.Payload, sec.FakeSNIPkt) ||
		ft.Seg2Delay != 123 {
		t.Fatalf("fakeTypeFromSection: mapping mismatch: %+v", ft)
	}
}

/* ---------- smoke test for sendFakeSequence ---------- */

func TestSendFakeSequence_NoPanic(t *testing.T) {
	sec := &config.Section{}
	ip, tcpTmpl := templateIPv4()
	ft := fakeType{
		SequenceLen: 0, // no packets really sent
		Payload:     []byte("x"),
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("sendFakeSequence panicked: %v", r)
		}
	}()
	sendFakeSequence(sec, ft, tcpTmpl, ip, nil)
}

/* ---------- new tests: MD5 option + payload source + delay routing ----- */

func TestBuildFake_MD5OptionAndWindowOverride_IPv4(t *testing.T) {
	ip, tcpTmpl := templateIPv4()
	ft := fakeType{
		Payload:     []byte("HELLO"),
		WinOverride: 4096,
		Strategy:    fakeStratTCPMD5,
	}
	raw, err := buildFake(tcpTmpl, ip, nil, ft.Payload /*flag*/, 0, tcpTmpl.Seq, ft)
	if err != nil {
		t.Fatalf("buildFake: %v", err)
	}
	ip4, _, tcp := decode(raw)
	if ip4 == nil || tcp == nil {
		t.Fatalf("decode failed")
	}
	// window must be overridden
	if tcp.Window != 4096 {
		t.Fatalf("window=%d want 4096", tcp.Window)
	}
	// options must contain MD5 (kind=19,len=18) and at least two NOPs; data offset > 5
	foundMD5, nop := false, 0
	for _, o := range tcp.Options {
		if o.OptionType == layers.TCPOptionKind(19) && o.OptionLength == 18 && len(o.OptionData) == 16 {
			foundMD5 = true
		}
		if o.OptionType == layers.TCPOptionKindNop {
			nop++
		}
	}
	if !foundMD5 || nop < 2 {
		t.Fatalf("MD5/NOP options not present as expected (foundMD5=%v, nop=%d)", foundMD5, nop)
	}
	if tcp.DataOffset <= 5 {
		t.Fatalf("DataOffset=%d want >5 (options added)", tcp.DataOffset)
	}
}

func TestSendFakeSequence_CustomPayloadChosen(t *testing.T) {
	// capture one packet
	var sent [][]byte
	orig := sendRaw
	sendRaw = func(b []byte) error { sent = append(sent, b); return nil }
	t.Cleanup(func() { sendRaw = orig })

	sec := &config.Section{
		FakeSNIType:   config.FakePayloadCustom,
		FakeCustomPkt: []byte("WORLD"),
	}
	ip, tcpTmpl := templateIPv4()
	ft := fakeType{
		SequenceLen: 1,
		Payload:     []byte("IGNORED"), // should be ignored
	}
	sendFakeSequence(sec, ft, tcpTmpl, ip, nil)
	if len(sent) != 1 {
		t.Fatalf("sent=%d want=1", len(sent))
	}
	_, _, tcp := decode(sent[0])
	if tcp == nil || len(tcp.Payload) != len(sec.FakeCustomPkt) {
		t.Fatalf("payload len=%d want=%d", len(tcp.Payload), len(sec.FakeCustomPkt))
	}
	if !bytes.Equal(tcp.Payload, sec.FakeCustomPkt) {
		t.Fatalf("payload=%q want=%q", tcp.Payload, sec.FakeCustomPkt)
	}
}

func TestSendFakeSequence_RandomPayloadLenRange(t *testing.T) {
	// record payload lengths
	var lens []int
	orig := sendRaw
	sendRaw = func(b []byte) error {
		_, _, tcp := decode(b)
		lens = append(lens, len(tcp.Payload))
		return nil
	}
	t.Cleanup(func() { sendRaw = orig })

	// deterministic RNG but we assert range anyway
	rand.Seed(1)

	sec := &config.Section{
		FakeSNIType: config.FakePayloadRandom,
	}
	ip, tcpTmpl := templateIPv4()
	ft := fakeType{
		SequenceLen: 3,
		Payload:     bytes.Repeat([]byte{'A'}, 100), // upper bound
	}
	sendFakeSequence(sec, ft, tcpTmpl, ip, nil)
	if len(lens) != 3 {
		t.Fatalf("sent=%d want=3", len(lens))
	}
	for i, n := range lens {
		if n < 1 || n > 100 {
			t.Fatalf("len[%d]=%d out of [1,100]", i, n)
		}
	}
}

func TestSendFakeSequence_RespectsSeg2Delay(t *testing.T) {
	var calls []string
	origRaw, origDel := sendRaw, sendDelayed
	sendRaw = func(_ []byte) error { calls = append(calls, "raw"); return nil }
	sendDelayed = func(_ []byte, _ uint) error { calls = append(calls, "delay"); return nil }
	t.Cleanup(func() { sendRaw, sendDelayed = origRaw, origDel })

	sec := &config.Section{}
	ip, tcpTmpl := templateIPv4()
	ft := fakeType{
		SequenceLen: 1,
		Payload:     []byte("X"),
	}
	// case: no delay
	calls = nil
	ft.Seg2Delay = 0
	sendFakeSequence(sec, ft, tcpTmpl, ip, nil)
	if len(calls) != 1 || calls[0] != "raw" {
		t.Fatalf("want raw, got %v", calls)
	}
	// case: delay set
	calls = nil
	ft.Seg2Delay = 50
	sendFakeSequence(sec, ft, tcpTmpl, ip, nil)
	if len(calls) != 1 || calls[0] != "delay" {
		t.Fatalf("want delay, got %v", calls)
	}
}

func TestTCP_InlineFake_PlainNoStrategyApplied(t *testing.T) {
	// Capture sends
	var sent [][]byte
	origSend := sendRaw
	sendRaw = func(b []byte) error { sent = append(sent, b); return nil }
	t.Cleanup(func() { sendRaw = origSend })

	// Minimal IPv4+TCP template
	ip := &layers.IPv4{
		SrcIP:    net.IP{10, 0, 0, 1},
		DstIP:    net.IP{10, 0, 0, 2},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 443,
		Seq:     1000,
		Window:  65535,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	// Only need SNI gating to pass; use brute mode so we don't rely on TLS encoding
	sec := &config.Section{
		TLSEnabled:            true,
		DPortFilter:           true,
		FragmentationStrategy: config.FragStratNone, // ensures inline fake path executes
		FakeSNI:               true,
		FakeSNISeqLen:         0, // no burst → only inline fake
		FakingStrategy:        config.FakeStratTTL | config.FakeStratTCPMD5 | config.FakeStratTCPCheck,
		FakingTTL:             5,
		SNIDetection:          1, // BRUTE mode
		SNIDomains:            []string{"example.com"},
	}

	// Payload with SNI present so brute finder succeeds; leaves bytes both before and after
	payload := []byte("prefix---example.com---suffix")

	// Run
	_ = processTCP(tcp, ip, nil, gopacket.Payload(payload), sec, nil)

	// Expect 3 sends: firstReal, inlineFake, secondReal
	if len(sent) != 3 {
		t.Fatalf("expected 3 sends (real, inline, real); got %d", len(sent))
	}

	// Inline fake is the middle packet
	ip4, _, tcpL := decode(sent[1])
	if ip4 == nil || tcpL == nil {
		t.Fatalf("decode inline fake failed")
	}

	// 1) TTL must be original (64), not sec.FakingTTL(5)
	if ip4.TTL != 64 {
		t.Fatalf("inline TTL changed: got %d, want 64", ip4.TTL)
	}
	// 2) No MD5 option (kind=19)
	for _, o := range tcpL.Options {
		if o.OptionType == layers.TCPOptionKind(19) {
			t.Fatalf("inline fake unexpectedly carries TCP MD5 option")
		}
	}
	// 3) No checksum nudge via URG pointer
	if tcpL.Urgent != 0 {
		t.Fatalf("inline fake unexpectedly nudged checksum via Urgent: %d", tcpL.Urgent)
	}
}

// --- chooseFakePayload coverage --------------------------------------------

func TestChooseFakePayload_Default_TruncatesToMaxLen(t *testing.T) {
	sec := &config.Section{FakeSNIType: config.FakePayloadDefault}
	fallback := bytes.Repeat([]byte{'A'}, 20)
	got := chooseFakePayload(sec, fallback, 5)
	if len(got) != 5 {
		t.Fatalf("default payload length=%d, want 5", len(got))
	}
	if !bytes.Equal(got, fallback[:5]) {
		t.Fatalf("default payload mismatch")
	}
}

func TestChooseFakePayload_Custom_Untruncated(t *testing.T) {
	sec := &config.Section{
		FakeSNIType:   config.FakePayloadCustom,
		FakeCustomPkt: []byte("CUSTOM-XXXX"),
	}
	fallback := bytes.Repeat([]byte{'A'}, 20)
	got := chooseFakePayload(sec, fallback, 3) // maxLen should NOT truncate custom
	if !bytes.Equal(got, sec.FakeCustomPkt) {
		t.Fatalf("custom payload not chosen or truncated: %q", got)
	}
}

func TestChooseFakePayload_Random_RespectsUpperBound(t *testing.T) {
	rand.Seed(1) // deterministic-ish
	sec := &config.Section{FakeSNIType: config.FakePayloadRandom}
	fallback := bytes.Repeat([]byte{'B'}, 100)

	got := chooseFakePayload(sec, fallback, 30)
	if len(got) < 1 || len(got) > 30 {
		t.Fatalf("random payload length=%d, want in [1,30]", len(got))
	}

	// Call again to ensure it indeed varies and still respects bounds
	got2 := chooseFakePayload(sec, fallback, 30)
	if len(got2) < 1 || len(got2) > 30 {
		t.Fatalf("random payload length(2)=%d, want in [1,30]", len(got2))
	}
	// Not strictly required, but nice to see variability
	if bytes.Equal(got, got2) && len(got) > 1 {
		t.Logf("note: random payloads happened to match; this can occur rarely")
	}
}
