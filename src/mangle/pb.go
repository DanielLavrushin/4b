package mangle

import (
	"bytes"
	"strings"

	"github.com/daniellavrushin/b4/config"
)

func findSNI(sec *config.Section, payload []byte) ([]byte, int, bool) {
	if sec.SNIDetection == 0 {
		host, err := extractSNI(payload)
		if err == nil && len(host) > 0 {
			if sec.MatchesSNI(string(host)) {
				off := bytes.Index(bytes.ToLower(payload), bytes.ToLower(host))
				if off < 0 {
					if len(payload) < 2 {
						return nil, 0, false
					}
					return host, 1, true
				}
				return host, off, true
			}
			lp := bytes.ToLower(payload)
			for _, dom := range sec.SNIDomains {
				d := []byte(strings.ToLower(dom))
				if len(d) == 0 {
					continue
				}
				if off := bytes.Index(lp, d); off >= 0 {
					return []byte(dom), off, true
				}
			}
			if sec.AllDomains > 0 {
				return nil, len(payload) / 2, true
			}
			return nil, 0, false
		}
		if sec.AllDomains > 0 {
			return nil, len(payload) / 2, true
		}
		lp := bytes.ToLower(payload)
		for _, dom := range sec.SNIDomains {
			d := []byte(strings.ToLower(dom))
			if len(d) == 0 {
				continue
			}
			if off := bytes.Index(lp, d); off >= 0 {
				return []byte(dom), off, true
			}
		}
		return nil, 0, false
	}

	if sec.AllDomains > 0 {
		return nil, len(payload) / 2, true
	}
	lp := bytes.ToLower(payload)
	for _, dom := range sec.SNIDomains {
		d := []byte(strings.ToLower(dom))
		if len(d) == 0 {
			continue
		}
		if off := bytes.Index(lp, d); off >= 0 {
			return []byte(dom), off, true
		}
	}
	return nil, 0, false
}
