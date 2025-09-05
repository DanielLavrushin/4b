package sni

import (
	"strings"
)

type SuffixSet struct {
	m map[string]struct{}
}

func NewSuffixSet(domains []string) *SuffixSet {
	m := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if strings.HasSuffix(d, ".") {
			d = strings.TrimRight(d, ".")
		}
		m[d] = struct{}{}
	}
	return &SuffixSet{m: m}
}

func (s *SuffixSet) Match(host string) bool {
	host = strings.ToLower(host)
	if host == "" {
		return false
	}
	if _, ok := s.m[host]; ok {
		return true
	}
	for i := 0; i < len(host); i++ {
		if host[i] == '.' {
			if _, ok := s.m[host[i+1:]]; ok {
				return true
			}
		}
	}
	return false
}
