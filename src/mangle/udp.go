package mangle

import (
	"math/rand"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func init() { rand.Seed(time.Now().UnixNano()) }

func processUDP(udp *layers.UDP, ip4 *layers.IPv4, ip6 *layers.IPv6,
	payload gopacket.Payload, sec *config.Section, origPacket []byte) Verdict {

	/* 1.  quick filter -------------------------------------------------- */
	if !udpFiltered(sec, udp, payload) {
		return VerdictContinue
	}

	/* 2.  decide action ------------------------------------------------- */
	switch sec.UDPMode {

	case config.UDPMODEDrop:
		return VerdictDrop

	case config.UDPMODEFake:
		// fire the fake burst
		sendFakeUDPSequence(sec, udp, ip4, ip6)

		// then forward the *real* packet exactly once
		_ = SendRaw(origPacket)
		return VerdictDrop // original must not reach kernel

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

func looksLikeQUIC(payload []byte) bool {
	return len(payload) >= 1200 && payload[0]&0xC0 == 0xC0
}

// decide whether we should mangle this UDP packet
func udpFiltered(sec *config.Section, udp *layers.UDP, payload []byte) bool {
	if !portAllowed(sec, udp.DstPort) {
		return false
	}

	switch sec.UDPFilterQuic {
	case config.UDPFilterQuicAll:
		return true
	case config.UDPFilterQuicParsed:
		return looksLikeQUIC(payload)
	default: // Disabled
		return true
	}
}

// build one forged UDP packet according to flags
func buildFakeUDP(tpl *layers.UDP, ip4 *layers.IPv4, ip6 *layers.IPv6,
	fakePayload []byte, sec *config.Section) ([]byte, error) {

	udp := *tpl // shallow copy

	if sec.UDPFakingStrategy&config.FakeStratUDPCheck != 0 {
		udp.Checksum++
	}

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
	return buf.Bytes(), nil
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
		_ = SendRaw(raw)
	}
}
