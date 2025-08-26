package mangle

import (
	"encoding/binary"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/logx"
	"github.com/daniellavrushin/b4/quic"
	"github.com/daniellavrushin/b4/tls"
	"github.com/google/gopacket/layers"
)

// allow tests to stub, like other parts of this package
var (
	quicIsInitial      = quic.IsInitial
	quicDecryptInitial = quic.DecryptInitial
	quicAssembleCrypto = quic.AssembleCrypto
	tlsExtractSNI      = tls.ExtractSNI
	extractSNIFromQUIC = tls.ExtractSNIFromQUIC
)

func quicParsedMatch(sec *config.Section, udp *layers.UDP, payload []byte) bool {
	if sec.DPortFilter && udp.DstPort != 443 {
		return false
	}
	if !quicIsInitial(payload) {
		logx.Tracef("QUIC: not Initial")
		return false
	}
	dcid := parseDCID(payload)
	if dcid == nil {
		logx.Tracef("QUIC: no DCID")
		return false
	}
	plain, ok := quicDecryptInitial(dcid, payload)
	if !ok {
		// also print version to debug v1 vs v2
		if len(payload) >= 5 {
			logx.Tracef("QUIC: decrypt failed, ver=%08x", binary.BigEndian.Uint32(payload[1:5]))
		}
		return false
	}
	crypto, ok := quicAssembleCrypto(dcid, plain)
	if !ok || len(crypto) == 0 {
		logx.Tracef("QUIC: no CRYPTO frames")
		return false
	}

	if sec.SNIDetection == 0 { // parse mode
		host, err := extractSNIFromQUIC(crypto) // TLS from QUIC CRYPTO (no TLS record layer)
		if err != nil {
			logx.Tracef("QUIC: SNI parse error: %v", err)
			return false
		}
		logx.Infof("QUIC SNI: %s", host)
		return sec.MatchesSNI(string(host))
	}

	if sec.AllDomains != 0 {
		logx.Infof("QUIC SNI: <any> (AllDomains)")
		return true
	}
	_, _, ok = findSNI(sec, crypto)
	if ok {
		logx.Infof("QUIC SNI: matched by brute list")
	}
	return ok
}

// parseDCID: flags(1) + ver(4) + DCID Len + DCID + ...
func parseDCID(b []byte) []byte {
	if len(b) < 7 || b[0]&0x80 == 0 {
		return nil
	}
	off := 1 + 4
	dlen := int(b[off])
	off++
	if len(b) < off+dlen {
		return nil
	}
	return b[off : off+dlen]
}

func processUDPQUIC(sec *config.Section, udp *layers.UDP, payload []byte) Verdict {

	if sec.DPortFilter && udp.DstPort != 443 {
		return VerdictContinue
	}

	switch sec.UDPFilterQuic {
	case config.UDPFilterQuicDisabled:
		return VerdictContinue

	case config.UDPFilterQuicAll:
		if sec.DPortFilter && udp.DstPort != 443 {
			return VerdictContinue
		}
		if sec.UDPMode == config.UDPMODEDrop {
			logx.Infof("QUIC: drop (all-mode) dport=%d", uint16(udp.DstPort))
			return VerdictDrop
		}
		return VerdictContinue

	case config.UDPFilterQuicParsed:
		if quicParsedMatch(sec, udp, payload) {
			if sec.UDPMode == config.UDPMODEDrop {
				return VerdictDrop
			}
			return VerdictContinue
		}
		if sec.UDPMode == config.UDPMODEDrop {
			logx.Tracef("QUIC: ambiguous or empty, force drop dport=%d", uint16(udp.DstPort))
			return VerdictDrop
		}
		return VerdictContinue
	}

	return VerdictContinue
}
