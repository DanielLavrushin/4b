package mangle

import (
	"net"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestProcessTCP_Brute_AllDomains_SplitsMiddle(t *testing.T) {
	var sent [][]byte
	origSend := sendRaw
	sendRaw = func(b []byte) error { sent = append(sent, b); return nil }
	t.Cleanup(func() { sendRaw = origSend })

	// no fakes, no delays
	sec := &config.Section{
		TLSEnabled:            true,
		SNIDetection:          1, // brute
		AllDomains:            1,
		FragmentationStrategy: config.FragStratNone,
		FakingStrategy:        0,
		FakeSNI:               false,
		DPortFilter:           false, // to avoid 443-only requirement
	}

	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2},
	}
	tcp := &layers.TCP{SrcPort: 1111, DstPort: 443, Seq: 1, ACK: true, DataOffset: 5, Window: 100}

	payloadBytes := []byte("ABCDEFGHIJKL") // len=12 → split in the middle (6/6)
	v := processTCP(tcp, ip4, nil, gopacket.Payload(payloadBytes), sec, nil)
	if v != VerdictDrop {
		t.Fatalf("verdict=%v want Drop", v)
	}
	if len(sent) != 2 {
		t.Fatalf("sent=%d want 2", len(sent))
	}

	// check lengths: 6 and 6
	_, _, p1 := decodeTCPv4(sent[0])
	_, _, p2 := decodeTCPv4(sent[1])
	if len(p1) != 6 || len(p2) != 6 {
		t.Fatalf("split lengths = %d and %d, want 6 and 6", len(p1), len(p2))
	}
}

func TestProcessTCP_Brute_ListMatch(t *testing.T) {
	var sent [][]byte
	origSend := sendRaw
	sendRaw = func(b []byte) error { sent = append(sent, b); return nil }
	t.Cleanup(func() { sendRaw = origSend })

	sec := &config.Section{
		TLSEnabled:            true,
		SNIDetection:          1, // brute
		SNIDomains:            []string{"example.com"},
		FragmentationStrategy: config.FragStratNone,
		FakingStrategy:        0,
		FakeSNI:               false,
		DPortFilter:           false,
	}

	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2},
	}
	tcp := &layers.TCP{SrcPort: 1111, DstPort: 443, Seq: 1, ACK: true, DataOffset: 5, Window: 100}

	payload := gopacket.Payload([]byte("XXexample.comYY"))
	v := processTCP(tcp, ip4, nil, payload, sec, nil)
	if v != VerdictDrop {
		t.Fatalf("verdict=%v want Drop", v)
	}
	if len(sent) != 2 {
		t.Fatalf("sent=%d want 2", len(sent))
	}
}
