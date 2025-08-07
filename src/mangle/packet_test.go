package mangle

import (
	"net"
	"testing"

	"github.com/daniellavrushin/4b/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ──────────────────────────────────────────────────────────────────────────────
// helpers to craft tiny packets
// ──────────────────────────────────────────────────────────────────────────────

// IPv4 + TCP (SYN)
func buildIPv4TCP() []byte {
	ip := &layers.IPv4{
		SrcIP:    net.IP{10, 0, 0, 1},
		DstIP:    net.IP{10, 0, 0, 2},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(1234),
		DstPort: layers.TCPPort(80),
		Seq:     11050,
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		ip, tcp, gopacket.Payload([]byte("hello")),
	)
	return buf.Bytes()
}

// IPv6 + UDP
func buildIPv6UDP() []byte {
	ip6 := &layers.IPv6{
		Version:    6,
		SrcIP:      net.IP{0x20, 0x01, 0x0d, 0xb8, 0xac, 0x10, 0xfe, 0x01, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:      net.IP{0x20, 0x01, 0x0d, 0xb8, 0xac, 0x10, 0xfe, 0x01, 0, 0, 0, 0, 0, 0, 0, 2},
		NextHeader: layers.IPProtocolUDP,
		HopLimit:   64,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(53000),
		DstPort: layers.UDPPort(443),
	}
	udp.SetNetworkLayerForChecksum(ip6)

	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		ip6, udp, gopacket.Payload([]byte("hello")),
	)
	return buf.Bytes()
}

// ──────────────────────────────────────────────────────────────────────────────
// tests
// ──────────────────────────────────────────────────────────────────────────────

func TestProcessPacketAccept(t *testing.T) {
	cfg := config.DefaultConfig // empty Sections() ⇒ no special rules

	cases := []struct {
		name string
		pkt  []byte
	}{
		{"IPv4/TCP", buildIPv4TCP()},
		{"IPv6/UDP", buildIPv6UDP()},
		{"Garbage/empty", []byte{0x00}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProcessPacket(&cfg, tc.pkt); got != VerdictAccept {
				t.Fatalf("expected VerdictAccept, got %v", got)
			}
		})
	}
}
