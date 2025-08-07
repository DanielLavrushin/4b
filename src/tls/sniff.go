package tls

import "github.com/daniellavrushin/4b/trie"

type Section struct {
	AllDomains bool
	SNIs       *trie.Matcher
	Exclude    *trie.Matcher
	BruteForce bool
}

func ScanTLSPayload(sec *Section, payload []byte) Verdict {
	var v Verdict

	if sec.BruteForce {
		ok, off, l := sec.SNIs.Match(payload, false)
		if ok {
			v.Target = true
			v.SNIPtr, v.SNILen = payload[off:off+l], l
			v.TargetSNIPtr, v.TargetSNILen = v.SNIPtr, l
		}
		return v
	}

	sni, err := ExtractSNI(payload)
	if err != nil {
		return v
	}
	v.SNIPtr, v.SNILen = sni, len(sni)

	if sec.AllDomains {
		v.Target = true
		v.TargetSNIPtr, v.TargetSNILen = sni, len(sni)
		return v
	}

	if ok, off, l := sec.SNIs.Match(sni, true); ok {
		v.Target = true
		v.TargetSNIPtr, v.TargetSNILen = sni[off:off+l], l
	}
	if v.Target {
		if ok, _, _ := sec.Exclude.Match(sni, true); ok {
			v.Target = false
		}
	}
	return v
}
