package mangle

import (
	"encoding/binary"
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

	tcph := *tcp
	tcph.Checksum = 0
	if sec.FKWinSize > 0 {
		tcph.Window = uint16(sec.FKWinSize)
	}

	var ipLayer gopacket.SerializableLayer
	if ip4 != nil {
		ipv4 = *ip4
		ipv4.Length = 0   // ask gopacket to fill
		ipv4.Checksum = 0 // ditto
		ipLayer = &ipv4
		_ = tcph.SetNetworkLayerForChecksum(&ipv4)
	} else {
		ipv6 = *ip6
		ipv6.Length = 0
		ipLayer = &ipv6
		_ = tcph.SetNetworkLayerForChecksum(&ipv6)
	}

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

	// 0. Find SNI according to detection mode
	sni, sniOff, ok := findSNI(sec, []byte(payload))
	if !ok {
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

	midOff := sniOff + len(sni)/2        // optional middle split
	splitAt := tcpPayloadOffset + sniOff // default first-byte of SNI

	if sec.FragMiddleSNI {
		splitAt = tcpPayloadOffset + midOff
	}
	if sec.FragmentationStrategy == config.FragStratIP {
		// IP fragments must start on an 8-byte boundary
		if rem := (splitAt - ipHdrLen) % 8; rem != 0 {
			splitAt += 8 - rem
		}
	}
	// dvs: bytes from TCP payload start to the split point
	dvs := splitAt - tcpPayloadOffset

	// 2. Choose fragmentation method ---------------------------------------
	switch sec.FragmentationStrategy {

	case config.FragStratIP:
		if ip4 == nil {
			break
		}
		// set TCP window on the whole packet first
		if sec.FKWinSize > 0 {
			if pkt, ok := overrideTCPWindow(origPacket, uint16(sec.FKWinSize)); ok {
				origPacket = pkt
			}
		}
		frag1, frag2, err := ip4FragFn(origPacket, splitAt-ipHdrLen)
		if err != nil {
			return VerdictAccept
		}
		sendFrags(sec, frag1, frag2, dvs, tcp, ip4, ip6)
		return VerdictDrop

	case config.FragStratTCP:
		frag1, frag2, err := tcpFragFn(origPacket, splitAt)
		if err != nil {
			return VerdictAccept
		}
		sendFrags(sec, frag1, frag2, dvs, tcp, ip4, ip6)
		return VerdictDrop

	default: // FragStratNone – fall back to existing pkt1/pkt2 logic
	}

	app := []byte(payload)

	firstLen := sniOff
	if sec.FragMiddleSNI {
		firstLen = sniOff + len(sni)/2
	}

	first := app[:firstLen]
	second := app[firstLen:]

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
		if sec.FKWinSize > 0 {
			tcph.Window = uint16(sec.FKWinSize)
		}

		var ipLayer gopacket.SerializableLayer
		if ip4 != nil {
			ipv4 = *ip4
			ipv4.Length, ipv4.Checksum = 0, 0
			ipLayer = &ipv4
			_ = tcph.SetNetworkLayerForChecksum(&ipv4)
		} else {
			ipv6 = *ip6
			ipv6.Length = 0
			ipLayer = &ipv6
			_ = tcph.SetNetworkLayerForChecksum(&ipv6)
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

	// 4.4  send real pieces with the fake burst *between* them
	firstReal, secondReal := pkt1, pkt2
	if sec.FragSNIReverse {
		firstReal, secondReal = pkt2, pkt1
	}
	_ = sendRaw(firstReal)
	{
		// optional raw fake ClientHello payload between the two real parts
		if sec.FakeSNI {
			if fake, err := build(sec.FakeSNIPkt, baseSeq); err == nil {
				_ = sendRaw(fake)
			}
		}
		// fake-sequence storm (RandSeq / PastSeq / TTL …), with RandSeqOff = dvs when requested
		ft := fakeTypeFromSection(sec)
		// for the default (non-frag) path, dvs equals the size of the first real payload part
		dvsLocal := len(first)
		if sec.FragSNIFaked {
			ft.RandSeqOff = dvsLocal
		}
		sendFakeSeq(ft, tcp, ip4, ip6)
	}
	if sec.Seg2Delay > 0 {
		_ = sendDelayed(secondReal, sec.Seg2Delay)
	} else {
		_ = sendRaw(secondReal)
	}

	return VerdictDrop
}

func sendFrags(sec *config.Section, a, b []byte, dvs int, tcp *layers.TCP, ip4 *layers.IPv4, ip6 *layers.IPv6) {
	if sec.FKWinSize > 0 {
		if ao, ok := overrideTCPWindow(a, uint16(sec.FKWinSize)); ok {
			a = ao
		}
		if bo, ok := overrideTCPWindow(b, uint16(sec.FKWinSize)); ok {
			b = bo
		}
	}
	first, second := a, b
	if sec.FragSNIReverse {
		first, second = b, a
	}
	_ = sendRaw(first)
	{
		// fake burst in the middle for frag paths as well
		ft := fakeTypeFromSection(sec)
		if sec.FragSNIFaked {
			ft.RandSeqOff = dvs
		}
		sendFakeSeq(ft, tcp, ip4, ip6)
	}
	if sec.Seg2Delay > 0 {
		_ = sendDelayed(second, sec.Seg2Delay)
	} else {
		_ = sendRaw(second)
	}
}

// overrideTCPWindow sets TCP.Window and fixes checksums.
// Returns (newRaw, true) only when it actually changed the packet.
func overrideTCPWindow(raw []byte, win uint16) ([]byte, bool) {
	// ---------- IPv4 first-fragment fast path ----------
	if len(raw) >= 20 && raw[0]>>4 == 4 {
		ihl := int(raw[0]&0x0F) * 4
		// L4=TCP?
		if ihl >= 20 && len(raw) >= ihl+20 && raw[9] == 6 {
			// flags+fragOffset @ bytes 6..7 (big-endian). low 13 bits = offset.
			frag := binary.BigEndian.Uint16(raw[6:8])
			if frag&0x1FFF != 0 { // not the first fragment -> no TCP header here
				return raw, false
			}
			tcpStart := ihl
			oldWin := binary.BigEndian.Uint16(raw[tcpStart+14 : tcpStart+16])
			if oldWin == win {
				return raw, false // already set
			}
			out := make([]byte, len(raw))
			copy(out, raw)

			// write new window
			binary.BigEndian.PutUint16(out[tcpStart+14:tcpStart+16], win)

			// RFC 1624 incremental update of TCP checksum
			oldCsum := binary.BigEndian.Uint16(out[tcpStart+16 : tcpStart+18])
			c := ^oldCsum
			c = onesAdd16(c, ^oldWin)
			c = onesAdd16(c, win)
			newCsum := ^c
			binary.BigEndian.PutUint16(out[tcpStart+16:tcpStart+18], newCsum)

			// IPv4 header checksum unchanged (we didn't touch it).
			return out, true
		}
	}

	// ---------- IPv6 / fallback via gopacket ----------
	try := func(first gopacket.LayerType) ([]byte, bool) {
		var ip4 layers.IPv4
		var ip6 layers.IPv6
		var tcp layers.TCP
		var app gopacket.Payload

		parser := gopacket.NewDecodingLayerParser(first, &ip4, &ip6, &tcp, &app)
		decoded := []gopacket.LayerType{}
		if err := parser.DecodeLayers(raw, &decoded); err != nil {
			return nil, false
		}
		hasTCP := false
		var ipL gopacket.SerializableLayer
		for _, lt := range decoded {
			switch lt {
			case layers.LayerTypeTCP:
				hasTCP = true
			case layers.LayerTypeIPv4:
				ipL = &ip4
			case layers.LayerTypeIPv6:
				ipL = &ip6
			}
		}
		if !hasTCP || ipL == nil {
			return nil, false
		}
		if tcp.Window == win { // nothing to do
			return raw, false
		}

		tcp.Window = win
		switch v := ipL.(type) {
		case *layers.IPv4:
			v.Length, v.Checksum = 0, 0
			_ = tcp.SetNetworkLayerForChecksum(v)
		case *layers.IPv6:
			v.Length = 0
			_ = tcp.SetNetworkLayerForChecksum(v)
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, ipL, &tcp, app); err != nil {
			return nil, false
		}
		return buf.Bytes(), true
	}

	if out, ok := try(layers.LayerTypeIPv4); ok {
		return out, true
	}
	if out, ok := try(layers.LayerTypeIPv6); ok {
		return out, true
	}
	return raw, false
}

// --- 16-bit one's complement add (carry wrap) ---
func onesAdd16(sum, v uint16) uint16 {
	s := uint32(sum) + uint32(v)
	s = (s & 0xFFFF) + (s >> 16)
	return uint16(s)
}
