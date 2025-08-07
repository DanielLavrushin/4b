package mangle

import (
	"net"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/* -----------------------------------------------------------------------
   lightweight stubs wired through the indirection variables
----------------------------------------------------------------------- */

var (
	rawCalls     [][]byte
	delayedCalls []struct {
		pkt   []byte
		delay uint
	}
)

func initTestStubs() func() {
	//------------------------------------------------------------------
	// 1) keep originals
	//------------------------------------------------------------------
	origSendRaw, origSendDelayed := sendRaw, sendDelayed
	origExtractSNI := extractSNI
	origFakeSeq := sendFakeSeq
	origIP4Frag := ip4FragFn
	origTCPFrag := tcpFragFn

	//------------------------------------------------------------------
	// 2) wipe previous state
	//------------------------------------------------------------------
	rawCalls = nil     // <‑‑ ADD
	delayedCalls = nil // <‑‑ ADD

	//------------------------------------------------------------------
	// 3) install stubs
	//------------------------------------------------------------------
	sendRaw = func(b []byte) error { rawCalls = append(rawCalls, b); return nil }
	sendDelayed = func(b []byte, d uint) error {
		delayedCalls = append(delayedCalls, struct {
			pkt   []byte
			delay uint
		}{append([]byte(nil), b...), d})
		return nil
	}
	extractSNI = func(_ []byte) ([]byte, error) { return []byte("example.com"), nil }
	sendFakeSeq = func(_ fakeType, _ *layers.TCP, _ *layers.IPv4, _ *layers.IPv6) {}
	ip4FragFn = func(_ []byte, _ int) ([]byte, []byte, error) { return nil, nil, nil }
	tcpFragFn = func(_ []byte, _ int) ([]byte, []byte, error) { return nil, nil, nil }

	//------------------------------------------------------------------
	// 4) restore helper
	//------------------------------------------------------------------
	return func() {
		sendRaw, sendDelayed = origSendRaw, origSendDelayed
		extractSNI = origExtractSNI
		sendFakeSeq = origFakeSeq
		ip4FragFn, tcpFragFn = origIP4Frag, origTCPFrag
	}
}

/* -----------------------------------------------------------------------
   helpers to craft a minimal IPv4/TCP ClientHello that contains "example.com"
----------------------------------------------------------------------- */

func buildPacket() (tcp *layers.TCP, ip *layers.IPv4, payload gopacket.Payload, full []byte) {
	ip = &layers.IPv4{
		Version:  4,
		IHL:      5,
		SrcIP:    net.IP{10, 0, 0, 1},
		DstIP:    net.IP{10, 0, 0, 2},
		Protocol: layers.IPProtocolTCP,
	}
	tcp = &layers.TCP{
		SrcPort: 12345,
		DstPort: 443,
		Seq:     1000,
		ACK:     false,
		SYN:     false,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	// payload contains the SNI so bytes.Index finds it
	payloadBytes := []byte("aaaexample.combbb")
	payload = gopacket.Payload(payloadBytes)

	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		ip, tcp, payload)
	full = buf.Bytes()
	return
}

/* -----------------------------------------------------------------------
   the test itself
----------------------------------------------------------------------- */

func TestProcessTCP_SplitsAndDrops(t *testing.T) {
	restore := initTestStubs()
	defer restore()

	// 1) craft packet layers
	tcp, ip, payload, full := buildPacket()

	// 2) section that matches "example.com" and asks for TCP fragmentation
	sec := config.NewSection(0)
	sec.SNIDomains = []string{"example.com"}
	sec.FragmentationStrategy = config.FragStratTCP
	sec.TLSEnabled = true
	sec.FragSNIReverse = false
	sec.DPortFilter = true // still allow dst 443

	// 3) run
	verdict := processTCP(tcp, ip, nil, payload, sec, full)
	if verdict != VerdictDrop {
		t.Fatalf("want VerdictDrop, got %v", verdict)
	}

	// 4) we expect exactly two real sends (pkt1, pkt2) and maybe fake seq
	if len(rawCalls) != 2 {
		t.Fatalf("expected 2 sendRaw calls, got %d", len(rawCalls))
	}
	if len(delayedCalls) != 0 {
		t.Fatalf("expected 0 sendDelayed calls, got %d", len(delayedCalls))
	}
}

/* -----------------------------------------------------------------------
   sanity check for sendAlteredSyn()
----------------------------------------------------------------------- */

func TestSendAlteredSyn_UsesSendRaw(t *testing.T) {
	restore := initTestStubs()
	defer restore()

	sec := config.NewSection(0)
	sec.SynFake = true
	sec.FakeSNIPkt = []byte{0xde, 0xad, 0xbe, 0xef}

	// minimal IPv4 SYN
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{1, 1, 1, 1}, DstIP: net.IP{2, 2, 2, 2},
	}
	tcp := &layers.TCP{SYN: true, DstPort: 443}
	tcp.SetNetworkLayerForChecksum(ip)

	vd := sendAlteredSyn(tcp, ip, nil, sec)
	if vd != VerdictDrop {
		t.Fatalf("want VerdictDrop, got %v", vd)
	}
	if len(rawCalls) != 1 {
		t.Fatalf("sendAlteredSyn should emit exactly 1 packet, got %d", len(rawCalls))
	}
}
