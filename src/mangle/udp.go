package mangle

import (
	"math/rand"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/quic"
	"github.com/daniellavrushin/b4/tls"
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

func udpFiltered(sec *config.Section, udp *layers.UDP, payload []byte) bool {
	// QUIC filter first (unless dport filter is on and port != 443)
	if sec.UDPFilterQuic != config.UDPFilterQuicDisabled {
		if !(sec.DPortFilter && uint16(udp.DstPort) != 443) {
			// Must be a long-header Initial in v1/v2, otherwise skip
			if quic.IsInitial(payload) {
				if sec.UDPFilterQuic == config.UDPFilterQuicAll {
					return true
				}

				// Parsed mode: decrypt → assemble CRYPTO → parse TLS CH → match SNI
				// Make a scratch copy; DecryptInitial mutates the header bytes.
				buf := make([]byte, len(payload))
				copy(buf, payload)

				// dcid is at buf[6 : 6+dcidLen]
				if len(buf) >= 6 {
					dlen := int(buf[5])
					if 6+dlen <= len(buf) {
						dcid := buf[6 : 6+dlen]
						if plain, ok := quic.DecryptInitial(dcid, buf); ok {
							if crypto, ok := quic.AssembleCrypto(plain); ok {
								if sec.SNIDetection == 1 { // brute
									v := tls.ScanTLSPayload(&tls.Section{
										BruteForce: true,
										SNIs:       nil, // not needed just to pull SNI
										Exclude:    nil,
									}, crypto)
									if v.SNILen > 0 && sec.MatchesSNI(string(v.SNIPtr[:v.SNILen])) {
										return true
									}
								} else {
									if host, err := tls.ExtractSNI(crypto); err == nil && len(host) > 0 && sec.MatchesSNI(string(host)) {
										return true
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Fall back to numeric dport ranges
	return portAllowed(sec, udp.DstPort)
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
