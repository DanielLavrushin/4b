package mangle

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// --- helpers -------------------------------------------------------------

// makeV1Initial returns the smallest buffer IsInitial() accepts for v1:
// long-header, type=Initial(0b00), version=0x00000001, dcid_len=0, scid_len=0.
// (QUIC long header format per RFC 9000; we only need the shape here.)
func makeV1Initial() []byte {
	b := make([]byte, 7)
	b[0] = 0x80 | (0x00 << 4) // long header + type=00 (v1 Initial)
	binary.BigEndian.PutUint32(b[1:5], 0x00000001)
	// b[5]=dcid_len=0, b[6]=scid_len=0
	return b
}

func newUDP(src, dst layers.UDPPort) *layers.UDP {
	u := &layers.UDP{SrcPort: src, DstPort: dst}
	return u
}

func newIPv4() *layers.IPv4 {
	return &layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{5, 6, 7, 8},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}
}

func newIPv6() *layers.IPv6 {
	return &layers.IPv6{
		SrcIP:      net.IP{0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:      net.IP{0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolUDP,
	}
}

// --- tests ---------------------------------------------------------------

func TestPortAllowed(t *testing.T) {
	sec := &config.Section{}
	if !portAllowed(sec, 53) { // empty ranges => allow all
		t.Fatal("expected allow when no ranges configured")
	}

	sec.UDPDPortRange = []config.UDPDPortRange{{Start: 1000, End: 2000}}
	if portAllowed(sec, 53) {
		t.Fatal("expected deny for port outside range")
	}
	if !portAllowed(sec, 1500) {
		t.Fatal("expected allow for port inside range")
	}
}

func TestUDPFiltered_QuicAll_AllowsInitial(t *testing.T) {
	sec := &config.Section{
		UDPFilterQuic: config.UDPFilterQuicAll,
		// DPortFilter off => we don't require port 443 here
	}
	udp := newUDP(12345, 443)
	initial := makeV1Initial()
	if !udpFiltered(sec, udp, initial) {
		t.Fatal("expected QUIC=all to approve Initial packet")
	}
}

func TestUDPFiltered_DPortFilter_SkipsQuicWhenNot443(t *testing.T) {
	sec := &config.Section{
		DPortFilter:   true,
		UDPFilterQuic: config.UDPFilterQuicAll,
		// restrict allowed ports to [40000,40010], so 53 should be denied
		UDPDPortRange: []config.UDPDPortRange{{Start: 40000, End: 40010}},
	}
	udp := newUDP(12345, 53) // not 443 → QUIC branch skipped
	initial := makeV1Initial()
	if udpFiltered(sec, udp, initial) {
		t.Fatal("expected deny: dport filter skips QUIC and port not allowed")
	}
}

func TestProcessUDP_ModeDrop(t *testing.T) {
	// Stub the raw sender to catch accidental sends in drop mode.
	sendCount := 0
	SetRawSendFunc(func(_ []byte) error { sendCount++; return nil })
	t.Cleanup(func() { SetRawSendFunc(nil) })

	sec := &config.Section{
		UDPMode: config.UDPMODEDrop,
		// QUIC disabled so we rely on ports; with no ranges => allowed
		UDPFilterQuic: config.UDPFilterQuicDisabled,
	}

	udp := newUDP(1111, 2222)
	v := processUDP(udp, newIPv4(), nil, gopacket.Payload(nil), sec, []byte{0xde, 0xad})
	if v != VerdictDrop {
		t.Fatalf("got %v, want VerdictDrop", v)
	}
	if sendCount != 0 {
		t.Fatalf("unexpected raw sends in drop mode: %d", sendCount)
	}
}

func TestProcessUDP_ModeFake_SendsBurstPlusOriginal(t *testing.T) {
	sends := 0
	SetRawSendFunc(func(_ []byte) error { sends++; return nil })
	t.Cleanup(func() { SetRawSendFunc(nil) })

	sec := &config.Section{
		UDPMode:           config.UDPMODEFake,
		UDPFakeSeqLen:     3,                            // burst size
		UDPFakeLen:        10,                           // payload length (zeros)
		UDPFilterQuic:     config.UDPFilterQuicDisabled, // rely on ports
		UDPDPortRange:     nil,                          // no ranges => allowed
		UDPFakingStrategy: 0,
	}

	udp := newUDP(1111, 2222)
	v := processUDP(udp, newIPv4(), nil, gopacket.Payload(nil), sec, []byte{0xca, 0xfe})
	if v != VerdictDrop {
		t.Fatalf("got %v, want VerdictDrop", v)
	}
	// 3 fakes + 1 original pass-through
	if sends != 4 {
		t.Fatalf("raw sends = %d, want 4", sends)
	}
}

func TestBuildFakeUDP_IPv4_TTLAndLengths(t *testing.T) {
	sec := &config.Section{
		UDPFakingStrategy: config.FakeStratTTL,
		FakingTTL:         9,
	}
	udp := newUDP(1234, 5678)
	ip := newIPv4()

	raw, err := buildFakeUDP(udp, ip, nil, make([]byte, 20), sec)
	if err != nil {
		t.Fatalf("buildFakeUDP: %v", err)
	}

	// decode and verify
	pkt := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
	ip4 := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	u := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)

	if ip4.TTL != sec.FakingTTL {
		t.Fatalf("IPv4 TTL=%d, want %d", ip4.TTL, sec.FakingTTL)
	}
	// length checks: UDP length = header(8) + payload(20)
	if int(u.Length) != 8+20 {
		t.Fatalf("UDP length=%d, want %d", u.Length, 28)
	}
}

func TestBuildFakeUDP_IPv6_HopLimitAndLengths(t *testing.T) {
	sec := &config.Section{
		UDPFakingStrategy: config.FakeStratTTL,
		FakingTTL:         7,
	}
	udp := newUDP(1234, 5678)
	ip := newIPv6()

	raw, err := buildFakeUDP(udp, nil, ip, make([]byte, 32), sec)
	if err != nil {
		t.Fatalf("buildFakeUDP: %v", err)
	}

	pkt := gopacket.NewPacket(raw, layers.LayerTypeIPv6, gopacket.Default)
	ip6 := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	u := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)

	if ip6.HopLimit != sec.FakingTTL {
		t.Fatalf("IPv6 HopLimit=%d, want %d", ip6.HopLimit, sec.FakingTTL)
	}
	if int(u.Length) != 8+32 {
		t.Fatalf("UDP length=%d, want %d", u.Length, 40)
	}
}
