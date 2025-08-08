// mangle/tcp_test.go
package mangle

import (
	"net"
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
