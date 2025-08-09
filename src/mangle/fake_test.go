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
