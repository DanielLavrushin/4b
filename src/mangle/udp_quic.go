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
	crypto, ok := quicAssembleCrypto(plain)
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
		logx.Infof("QUIC SNI: %s", host) // <— SEE IT HERE
		return sec.MatchesSNI(string(host))
	}

	if sec.AllDomains != 0 {
		logx.Infof("QUIC SNI: <any> (AllDomains)") // optional
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

// processUDPQUIC turns the QUIC gating decision into a Verdict.
// Call this from your UDP handler with the parsed UDP header and the UDP payload.
func processUDPQUIC(sec *config.Section, udp *layers.UDP, payload []byte) Verdict {
	switch sec.UDPFilterQuic {
	case config.UDPFilterQuicDisabled:
		return VerdictContinue
	case config.UDPFilterQuicAll:
		// proceed unconditionally
	case config.UDPFilterQuicParsed:
		if !quicParsedMatch(sec, udp, payload) {
			return VerdictContinue
		}
	}

	if sec.UDPMode == config.UDPMODEDrop {
		return VerdictDrop
	}

	// UDPMODEFake: allow main UDP path to run fake burst + forward original
	return VerdictContinue
}
