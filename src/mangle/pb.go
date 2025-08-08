package mangle

import (
	"bytes"
	"strings"

	"github.com/daniellavrushin/b4/config"
)

//   - parse mode: SNI from TLS ClientHello and its offset in payload
//   - brute mode: first matching domain's offset in payload (case-insensitive);
//     if AllDomains>0, splits in the middle (sniOff = len/2)
func findSNI(sec *config.Section, payload []byte) ([]byte, int, bool) {
	// 0 = parse, anything else = brute
	if sec.SNIDetection == 0 {
		host, err := extractSNI(payload)
		if err != nil {
			return nil, 0, false
		}
		if !sec.MatchesSNI(string(host)) {
			return nil, 0, false
		}
		off := bytes.Index(payload, host)
		if off < 0 {
			off = 1
		}
		return host, off, true
	}

	// brute
	if sec.AllDomains != 0 {
		return nil, len(payload) / 2, true
	}

	lp := bytes.ToLower(payload)
	for _, dom := range sec.SNIDomains {
		d := []byte(strings.ToLower(dom))
		if len(d) == 0 {
			continue
		}
		if off := bytes.Index(lp, d); off >= 0 {
			// use original-case dom for sni bytes (not really used except length)
			return []byte(dom), off, true
		}
	}
	return nil, 0, false
}
