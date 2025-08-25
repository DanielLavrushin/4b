package mangle

import (
	"encoding/binary"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/logx"
	"github.com/daniellavrushin/b4/tls"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	sendRaw     = func(b []byte) error { return SendRaw(b) }
	sendDelayed = func(b []byte, d uint) error { return SendDelayed(b, d) }
	ip4FragFn   = ip4Frag
	tcpFragFn   = tcpFrag
	extractSNI  = tls.ExtractSNI
	sendFakeSeq = sendFakeSequence
)

func sendAlteredSyn(tcp *layers.TCP, ip4 *layers.IPv4, ip6 *layers.IPv6,
	sec *config.Section) Verdict {

	// 1. Decide payload
	payload := chooseFakePayload(sec, sec.FakeSNIPkt, int(sec.SynFakeLen))

	logx.Tracef("tcp: SYN alter (sec=%d) payloadLen=%d winOverride=%d ipver=%d",
		sec.ID, len(payload), sec.FKWinSize, func() int {
			if ip4 != nil {
				return 4
			}
			return 6
		}())

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
		logx.Errorf("failed to serialize TCP SYN packet: %v", err)
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

	// Реальный TCP payload берём из сырого пакета, как в C (tcp_payload_split)
	tcpPayload, ok2 := splitTCP(origPkt)
	if !ok2 || len(tcpPayload) == 0 {
		return VerdictContinue
	}
	logx.Tracef("TCP payload seen: dport=%d, len=%d", tcp.DstPort, len(tcpPayload))
	// 0. Find SNI according to detection mode (parse/brute/AllDomains)
	sni, sniOff, ok := findSNI(sec, tcpPayload)
	if !ok {
		return VerdictContinue
	}

	logx.Infof("TCP SNI: %s (sec=%d)", sni, sec.ID)

	// 1. Calculate offsets -------------------------------------------------

	if !sec.MatchesSNI(string(sni)) {
		return VerdictContinue
	}

	origPacket := origPkt
	tcpHdrLen := int(tcp.DataOffset) * 4
	ipHdrLen := 0
	if ip4 != nil {
		ipHdrLen = int(ip4.IHL) * 4
	} else {
		ipHdrLen = 40
	} // IPv6 fixed 40
	tcpPayloadOffset := ipHdrLen + tcpHdrLen

	// 1a. Build candidate first-part lengths (relative to TCP payload start)
	// base at start of SNI
	base := sniOff
	candidates := make([]int, 0, 2)
	if sec.FragSNIPos > 0 && sec.FragSNIPos < len(sni) {
		candidates = append(candidates, base+sec.FragSNIPos)
	}
	if sec.FragMiddleSNI {
		candidates = append(candidates, base+len(sni)/2)
	}
	if len(candidates) == 0 {
		candidates = append(candidates, base) // default: split at SNI start
	}
	// de-dup while preserving order
	{
		seen := make(map[int]bool, len(candidates))
		uniq := candidates[:0]
		for _, v := range candidates {
			if !seen[v] {
				seen[v] = true
				uniq = append(uniq, v)
			}
		}
		candidates = uniq
	}

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
		for _, firstLen := range candidates {
			if firstLen <= 0 {
				continue
			}
			// absolute split position in whole packet
			splitAt := tcpPayloadOffset + firstLen
			cut := splitAt - ipHdrLen // offset within IP payload
			// IP fragments must start on an 8-byte boundary (from IP payload start)
			if rem := cut % 8; rem != 0 {
				cut += 8 - rem
			}
			frag1, frag2, err := ip4FragFn(origPacket, cut)
			if err != nil {
				continue
			}
			dvs := cut - tcpHdrLen // bytes of TCP payload in the first frag
			if dvs < 0 {
				dvs = 0
			}
			sendFrags(sec, frag1, frag2, dvs, tcp, ip4, ip6)
			return VerdictDrop
		}
		return VerdictAccept

	case config.FragStratTCP:
		for _, firstLen := range candidates {
			if firstLen <= 0 {
				continue
			}
			splitAt := tcpPayloadOffset + firstLen
			frag1, frag2, err := tcpFragFn(origPacket, splitAt)
			if err != nil {
				continue
			}
			dvs := firstLen
			sendFrags(sec, frag1, frag2, dvs, tcp, ip4, ip6)
			return VerdictDrop
		}
		return VerdictAccept

	default: // FragStratNone – fall back to existing pkt1/pkt2 logic
	}

	app := tcpPayload

	// helper to actually build and send for a chosen firstLen
	tryNonFrag := func(firstLen int) bool {
		if firstLen < 0 || firstLen > len(app) {
			return false
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
			logx.Errorf("fragment build: %v %v", err1, err2)
			return false
		}

		// 4.4  send real pieces with the fake burst *between* them
		firstReal, secondReal := pkt1, pkt2
		if sec.FragSNIReverse {
			firstReal, secondReal = pkt2, pkt1
		}
		_ = sendRaw(firstReal)
		{
			if sec.FakeSNI {
				fakePayload := chooseFakePayload(sec, sec.FakeSNIPkt, 0)
				if fake, err := build(fakePayload, baseSeq); err == nil {
					_ = sendRaw(fake)
				}
			}
			ft := fakeTypeFromSection(sec)
			dvsLocal := len(first) // equals chosen firstLen
			if sec.FragSNIFaked || sec.FragTwoStage {
				ft.RandSeqOff = dvsLocal
			}
			sendFakeSeq(sec, ft, tcp, ip4, ip6)
		}

		dvsLocal := len(first)
		if sec.Seg2Delay > 0 && ((dvsLocal > 0) != sec.FragSNIReverse) {
			_ = sendDelayed(secondReal, sec.Seg2Delay)
		} else {
			_ = sendRaw(secondReal)
		}
		return true
	}

	for _, firstLen := range candidates {
		if tryNonFrag(firstLen) {
			return VerdictDrop

		}
	}
	return VerdictAccept
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
		if sec.FragSNIFaked || sec.FragTwoStage {
			ft.RandSeqOff = dvs
		}
		sendFakeSeq(sec, ft, tcp, ip4, ip6)
	}
	if sec.Seg2Delay > 0 && ((dvs > 0) != sec.FragSNIReverse) {
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

	// ---------- IPv6 fast path (no extension headers) ----------
	if len(raw) >= 40 && (raw[0]>>4) == 6 && raw[6] == 6 { // IPv6 + NextHeader=TCP
		out := make([]byte, len(raw))
		copy(out, raw)

		tcpStart := 40 // fixed IPv6 header
		if len(out) < tcpStart+20 {
			return raw, false
		}

		oldWin := binary.BigEndian.Uint16(out[tcpStart+14 : tcpStart+16])
		if oldWin == win {
			return raw, false // already set
		}

		// Write new window
		binary.BigEndian.PutUint16(out[tcpStart+14:tcpStart+16], win)

		// Recompute TCP checksum with IPv6 pseudo-header
		out[tcpStart+16], out[tcpStart+17] = 0, 0
		tcpLen := len(out) - tcpStart

		// Pseudo header: src(16) dst(16) upper-len(4) zeros(3) next(1)
		var pseudo [40]byte
		copy(pseudo[0:16], out[8:24])   // src
		copy(pseudo[16:32], out[24:40]) // dst
		pseudo[32] = byte(uint32(tcpLen) >> 24)
		pseudo[33] = byte(uint32(tcpLen) >> 16)
		pseudo[34] = byte(uint32(tcpLen) >> 8)
		pseudo[35] = byte(uint32(tcpLen))
		// pseudo[36..38] left as zero
		pseudo[39] = 6 // TCP

		sum := sum16(pseudo[:]) + sum16(out[tcpStart:])
		cs := finalize(sum)
		out[tcpStart+16] = byte(cs >> 8)
		out[tcpStart+17] = byte(cs)

		// (No IPv6 header checksum)
		return out, true
	}

	// ---------- IPv{4,6} / fallback via gopacket ----------
	try := func(first gopacket.LayerType) ([]byte, bool) {
		// Parse the packet (IPv4 or IPv6) using the generic decoder.
		p := gopacket.NewPacket(raw, first, gopacket.Default)
		if p.ErrorLayer() != nil {
			return nil, false
		}

		// Find IP and TCP layers
		var ipL gopacket.SerializableLayer
		var ip4 layers.IPv4
		var ip6 layers.IPv6

		if l := p.Layer(layers.LayerTypeIPv4); l != nil {
			ip4 = *l.(*layers.IPv4)
			ipL = &ip4
		} else if l := p.Layer(layers.LayerTypeIPv6); l != nil {
			ip6 = *l.(*layers.IPv6)
			ipL = &ip6
		} else {
			return nil, false
		}

		tl := p.Layer(layers.LayerTypeTCP)
		if tl == nil {
			return nil, false
		}
		tcph := *(tl.(*layers.TCP)) // editable copy

		// No change needed? bail out (signals "unchanged")
		if tcph.Window == win {
			return raw, false
		}
		tcph.Window = win

		// Wire up checksums for re-serialize
		switch v := ipL.(type) {
		case *layers.IPv4:
			v.Length, v.Checksum = 0, 0
			_ = tcph.SetNetworkLayerForChecksum(v)
		case *layers.IPv6:
			v.Length = 0
			_ = tcph.SetNetworkLayerForChecksum(v)
		}

		// Preserve app payload (extensions may be dropped on re-serialize — OK)
		var app []byte
		if al := p.ApplicationLayer(); al != nil {
			app = al.Payload()
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, ipL, &tcph, gopacket.Payload(app)); err != nil {
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

// --- tiny checksum helpers (used by IPv6 fast path) ---
func sum16(b []byte) uint32 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	return s
}

func finalize(s uint32) uint16 {
	for s>>16 != 0 {
		s = (s & 0xFFFF) + (s >> 16)
	}
	return ^uint16(s)
}

// --- 16-bit one's complement add (carry wrap) ---
func onesAdd16(sum, v uint16) uint16 {
	s := uint32(sum) + uint32(v)
	s = (s & 0xFFFF) + (s >> 16)
	return uint16(s)
}
