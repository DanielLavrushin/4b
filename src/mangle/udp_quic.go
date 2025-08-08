package mangle

import (
	"github.com/daniellavrushin/b4/config"
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
)

func quicParsedMatch(sec *config.Section, udp *layers.UDP, payload []byte) bool {
	// Respect TLS dport filter like C does (443 only)
	if sec.DPortFilter && udp.DstPort != 443 {
		return false
	}
	if !quicIsInitial(payload) {
		return false
	}

	dcid := parseDCID(payload)
	if dcid == nil {
		return false
	}
	// DecryptInitial is non-mutating; pass payload directly
	plain, ok := quicDecryptInitial(dcid, payload)
	if !ok {
		return false
	}

	crypto, ok := quicAssembleCrypto(plain)
	if !ok || len(crypto) == 0 {
		return false
	}

	// SNI decision mode
	if sec.SNIDetection == 0 { // parse
		host, err := tlsExtractSNI(crypto)
		if err != nil {
			return false
		}
		return sec.MatchesSNI(string(host))
	}

	// brute
	if sec.AllDomains != 0 {
		return true // accept any SNI (C’s MatchesSNI would accept everything)
	}
	_, _, ok = findSNI(sec, crypto) // reuse our brute finder on CRYPTO bytes
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
