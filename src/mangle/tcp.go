package mangle

import (
	"bytes"
	"log"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/tls"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	sendRaw     = SendRaw
	sendDelayed = SendDelayed
	ip4FragFn   = ip4Frag
	tcpFragFn   = tcpFrag
	extractSNI  = tls.ExtractSNI
	sendFakeSeq = sendFakeSequence
)

func sendAlteredSyn(tcp *layers.TCP, ip4 *layers.IPv4, ip6 *layers.IPv6,
	sec *config.Section) Verdict {

	// 1. Decide payload
	payload := sec.FakeSNIPkt
	if n := int(sec.SynFakeLen); n != 0 && n < len(payload) {
		payload = payload[:n]
	}

	// 2. Make editable header copies
	var (
		ipv4 layers.IPv4
		ipv6 layers.IPv6
	)

	var ipLayer gopacket.SerializableLayer
	if ip4 != nil {
		ipv4 = *ip4
		ipv4.Length = 0   // ask gopacket to fill
		ipv4.Checksum = 0 // ditto
		ipLayer = &ipv4
	} else {
		ipv6 = *ip6
		ipv6.Length = 0
		ipLayer = &ipv6
	}

	tcph := *tcp
	tcph.Checksum = 0

	// 3. Serialize with checksum support
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true, // <-- HERE
	}

	if err := gopacket.SerializeLayers(
		buf, opts, ipLayer, &tcph, gopacket.Payload(payload),
	); err != nil {
		log.Printf("syn-fake serialize: %v", err)
		return VerdictAccept
	}

	raw := buf.Bytes()

	if err := sendRaw(raw); err != nil {
		return VerdictAccept
	}
	return VerdictDrop
}

// processTCP decides what to do with a single TCP packet.
func processTCP(tcp *layers.TCP, ip4 *layers.IPv4, ip6 *layers.IPv6,
	payload gopacket.Payload, sec *config.Section, origPkt []byte) Verdict {

	// --- fast filters -------------------------------------------------
	if sec.DPortFilter && tcp.DstPort != 443 {
		return VerdictAccept
	}
	if tcp.SYN {
		if sec.SynFake {
			return sendAlteredSyn(tcp, ip4, ip6, sec)
		}
		return VerdictContinue
	}
	if !sec.TLSEnabled {
		// no reason to parse TLS at all
		return VerdictContinue
	}

	// 0. TLS ClientHello → grab SNI
	sni, err := extractSNI(payload)
	if err != nil {
		return VerdictContinue
	}

	if !sec.MatchesSNI(string(sni)) {
		return VerdictContinue
	}

	origPacket := origPkt

	// 1. Calculate offsets -------------------------------------------------
	tcpHdrLen := int(tcp.DataOffset) * 4
	ipHdrLen := 0
	if ip4 != nil {
		ipHdrLen = int(ip4.IHL) * 4
	} else {
		ipHdrLen = 40
	} // IPv6 fixed 40
	tcpPayloadOffset := ipHdrLen + tcpHdrLen

	sniOff := bytes.Index(payload, sni)
	midOff := sniOff + len(sni)/2        // optional middle split
	splitAt := tcpPayloadOffset + sniOff // default first-byte of SNI

	if sec.FragMiddleSNI {
		splitAt = tcpPayloadOffset + midOff
	}
	if sec.FragmentationStrategy == config.FragStratIP {
		// IP fragments must start on an 8-byte boundary
		if rem := (splitAt - tcpHdrLen) % 8; rem != 0 {
			splitAt += 8 - rem
		}
	}

	// 2. Choose fragmentation method ---------------------------------------
	switch sec.FragmentationStrategy {

	case config.FragStratIP:
		if ip4 == nil {
			break
		}
		frag1, frag2, err := ip4FragFn(origPacket, splitAt-ipHdrLen)
		if err != nil {
			return VerdictAccept
		}
		sendFrags(sec, frag1, frag2) // helper from previous message
		return VerdictDrop           // we’re done

	case config.FragStratTCP:
		frag1, frag2, err := tcpFragFn(origPacket, splitAt)
		if err != nil {
			return VerdictAccept
		}
		sendFrags(sec, frag1, frag2)
		return VerdictDrop

	default: // FragStratNone – fall back to your existing pkt1/pkt2 logic
	}

	app := payload // full TCP application payload
	sniOff = bytes.Index(app, sni)
	if sniOff == -1 {
		// Fallback: split after 1 byte of payload
		sniOff = 1
	}
	mid := sniOff + len(sni)/2

	first := app[:mid]
	second := app[mid:]

	// 4.2  helper: serialise a full packet with *data* as payload and
	//      *seq* as sequence number.  Returns the raw wire bytes.
	build := func(data []byte, seq uint32) ([]byte, error) {
		var (
			ipv4 layers.IPv4
			ipv6 layers.IPv6
			tcph layers.TCP = *tcp
		)
		tcph.Seq = seq
		tcph.ACK = false
		tcph.SYN = false

		var ipLayer gopacket.SerializableLayer
		if ip4 != nil {
			ipv4 = *ip4
			ipv4.Length, ipv4.Checksum = 0, 0
			ipLayer = &ipv4
		} else {
			ipv6 = *ip6
			ipv6.Length = 0
			ipLayer = &ipv6
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		if err := gopacket.SerializeLayers(
			buf, opts, ipLayer, &tcph, gopacket.Payload(data),
		); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	// 4.3  craft the two real segments
	baseSeq := tcp.Seq
	pkt1, err1 := build(first, baseSeq)
	pkt2, err2 := build(second, baseSeq+uint32(len(first)))

	if err1 != nil || err2 != nil {
		log.Printf("fragment build: %v %v", err1, err2)
		return VerdictAccept
	}

	// 4.4  optionally craft & send the *fake* SNI before real ones
	if sec.FakeSNI {
		fake, err := build(sec.FakeSNIPkt, baseSeq)
		if err == nil {
			_ = sendRaw(fake) // ignore error
		}
	}

	// 4.4b  full fake-sequence storm (RandSeq / PastSeq / TTL …)
	sendFakeSeq(fakeTypeFromSection(sec), tcp, ip4, ip6)

	// 4.5  send the real pieces (order may be reversed if requested)
	if sec.FragSNIReverse {
		_ = sendRaw(pkt2)
		if sec.Seg2Delay > 0 {
			_ = sendDelayed(pkt1, sec.Seg2Delay)
		} else {
			_ = sendRaw(pkt1)
		}
	} else { // normal order
		_ = sendRaw(pkt1)
		if sec.Seg2Delay > 0 {
			_ = sendDelayed(pkt2, sec.Seg2Delay)
		} else {
			_ = sendRaw(pkt2)
		}
	}

	return VerdictDrop
}

func sendFrags(sec *config.Section, a, b []byte) {
	if sec.FragSNIReverse {
		_ = sendRaw(b)
		if sec.Seg2Delay > 0 {
			_ = sendDelayed(a, sec.Seg2Delay)
		} else {
			_ = sendRaw(a)
		}
	} else {
		_ = sendRaw(a)
		if sec.Seg2Delay > 0 {
			_ = sendDelayed(b, sec.Seg2Delay)
		} else {
			_ = sendRaw(b)
		}
	}
}
