package mangle

import (
	"encoding/binary"
	"math/rand"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/logx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func init() { rand.Seed(time.Now().UnixNano()) }

func ProcessUDP(udp *layers.UDP, ip4 *layers.IPv4, ip6 *layers.IPv6,
	payload gopacket.Payload, sec *config.Section, origPkt []byte) Verdict {
	return processUDP(udp, ip4, ip6, payload, sec, origPkt)
}

func processUDP(udp *layers.UDP, ip4 *layers.IPv4, ip6 *layers.IPv6,
	payload gopacket.Payload, sec *config.Section, origPacket []byte) Verdict {

	if !fromLAN(ip4, ip6) {
		return VerdictContinue
	}

	if v := processUDPQUIC(sec, udp, []byte(payload)); v != VerdictContinue {
		return v
	}

	if !udpFiltered(sec, udp, []byte(payload)) {
		return VerdictContinue
	}

	logx.Tracef("processing UDP packet: ip4=%v, ip6=%v, payload lenght=%d", ip4 != nil, ip6 != nil, len(payload))

	switch sec.UDPMode {

	case config.UDPMODEDrop:
		return VerdictDrop

	case config.UDPMODEFake:
		sendFakeUDPSequence(sec, udp, ip4, ip6)
		_ = sendRaw(origPacket)
		return VerdictDrop

	default:
		return VerdictContinue
	}
}

/* ------------------------------------------------------------------ */

func portAllowed(sec *config.Section, p layers.UDPPort) bool {
	if len(sec.UDPDPortRange) == 0 {
		return true
	}
	for _, r := range sec.UDPDPortRange {
		if uint16(p) >= r.Start && uint16(p) <= r.End {
			return true
		}
	}
	return false
}

func udpFiltered(sec *config.Section, udp *layers.UDP, payload []byte) bool {
	if sec.UDPFilterQuic != config.UDPFilterQuicDisabled {
		if !(sec.DPortFilter && uint16(udp.DstPort) != 443) {
			switch sec.UDPFilterQuic {
			case config.UDPFilterQuicAll:
				return true
			case config.UDPFilterQuicParsed:
				return quicParsedMatch(sec, udp, payload)
			}
		}
	}

	return portAllowed(sec, udp.DstPort)
}

func buildFakeUDP(tpl *layers.UDP, ip4 *layers.IPv4, ip6 *layers.IPv6,
	fakePayload []byte, sec *config.Section) ([]byte, error) {

	udp := *tpl // shallow copy

	var ipL gopacket.SerializableLayer
	if ip4 != nil {
		ip := *ip4
		if sec.UDPFakingStrategy&config.FakeStratTTL != 0 {
			ip.TTL = sec.FakingTTL
		}
		ipL = &ip
		udp.SetNetworkLayerForChecksum(&ip)
	} else {
		ip := *ip6
		if sec.UDPFakingStrategy&config.FakeStratTTL != 0 {
			ip.HopLimit = sec.FakingTTL
		}
		ipL = &ip
		udp.SetNetworkLayerForChecksum(&ip)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ipL, &udp, gopacket.Payload(fakePayload)); err != nil {
		return nil, err
	}
	raw := buf.Bytes()
	// Nudge checksum AFTER compute (like C: udph->check += 1)
	off := 0
	if ip4 != nil {
		off = int(ip4.IHL) * 4
	} else {
		off = 40
	}
	if len(raw) >= off+8 && (sec.UDPFakingStrategy&config.FakeStratUDPCheck) != 0 {
		c := binary.BigEndian.Uint16(raw[off+6 : off+8])
		c++
		binary.BigEndian.PutUint16(raw[off+6:off+8], c)
	}
	return raw, nil
}

// full fake sequence (the nested for-loop from C code)
func sendFakeUDPSequence(sec *config.Section, udp *layers.UDP,
	ip4 *layers.IPv4, ip6 *layers.IPv6) {

	// Dummy payload: just sec.UDPFakeLen zeroes
	fakeBody := make([]byte, sec.UDPFakeLen)

	for i := uint(0); i < sec.UDPFakeSeqLen; i++ {
		raw, err := buildFakeUDP(udp, ip4, ip6, fakeBody, sec)
		if err != nil {
			continue
		}
		_ = sendRaw(raw)
	}
}

func fromLAN(ip4 *layers.IPv4, ip6 *layers.IPv6) bool {
	if ip4 != nil {
		b := ip4.SrcIP
		// RFC1918
		if b[0] == 10 || (b[0] == 192 && b[1] == 168) || (b[0] == 172 && (b[1]&0xF0) == 16) {
			return true
		}
		return false
	}
	if ip6 != nil {
		// ULA fc00::/7
		return (ip6.SrcIP[0] & 0xFE) == 0xFC
	}
	return false
}
