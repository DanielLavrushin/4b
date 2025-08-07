package mangle

import (
	"bytes"
	"encoding/binary"
	"math/rand"
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
		SrcIP:    []byte{1, 1, 1, 1},
		DstIP:    []byte{2, 2, 2, 2},
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
		SrcIP:      bytes.Repeat([]byte{0x11}, 16),
		DstIP:      bytes.Repeat([]byte{0x22}, 16),
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
	sendFakeSequence(ft, tcpTmpl, ip, nil)
}

/* ---------- init ---------- */

func init() {
	// ensure deterministic RandSeq test
	rand.Seed(time.Now().UnixNano())
}
