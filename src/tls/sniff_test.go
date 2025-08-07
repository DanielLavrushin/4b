package tls

import (
	"bytes"
	"testing"

	"github.com/daniellavrushin/b4/trie"
)

/* ---------- helpers ---------- */

// buildMatcher returns a *trie.Matcher populated with the given hosts.
func buildMatcher(pats ...string) *trie.Matcher {
	m := trie.NewMatcher()
	for _, p := range pats {
		m.Insert([]byte(p))
	}
	return m
}

// clientHello builds a minimal TLS-1.2 ClientHello whose record header
// includes the single-byte “gap” that ExtractSNI expects.
func clientHello(host string) []byte {
	h := []byte(host)

	// ----- SNI extension -----
	name := append([]byte{0x00, byte(len(h) >> 8), byte(len(h))}, h...)
	nameList := append([]byte{byte(len(name) >> 8), byte(len(name))}, name...)
	ext := append([]byte{0x00, 0x00, byte(len(nameList) >> 8), byte(len(nameList))}, nameList...)

	// ----- ClientHello body -----
	body := make([]byte, 0, 64)
	body = append(body, 0x03, 0x03)                        // legacy_version
	body = append(body, bytes.Repeat([]byte{0x00}, 32)...) // random
	body = append(body, 0x00)                              // session-id len
	body = append(body, 0x00, 0x02, 0x13, 0x01)            // cipher-suites
	body = append(body, 0x01, 0x00)                        // compression
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	// ----- handshake wrapper -----
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	// ----- record header (6-byte legacy layout) -----
	rec := []byte{
		0x16,       // ContentType = Handshake
		0x03,       // gap byte (skipped by parser)
		0x03, 0x03, // legacy_version
		byte(len(hs) >> 8), byte(len(hs)),
	}
	return append(rec, hs...)
}

/* ---------- tests ---------- */

func TestScanTLSPayload_BruteForceMatch(t *testing.T) {
	domain := "blocked.example"
	payload := []byte("abc " + domain + " xyz")

	sec := &Section{
		SNIs:       buildMatcher(domain),
		Exclude:    buildMatcher(),
		BruteForce: true,
	}

	v := ScanTLSPayload(sec, payload)
	if !v.Target {
		t.Fatalf("expected Target==true")
	}
	if got := string(v.TargetSNIPtr); got != domain {
		t.Fatalf("got SNI %q, want %q", got, domain)
	}
}

func TestScanTLSPayload_BruteForceNoMatch(t *testing.T) {
	sec := &Section{
		SNIs:       buildMatcher("blocked.example"),
		Exclude:    buildMatcher(),
		BruteForce: true,
	}
	if v := ScanTLSPayload(sec, []byte("harmless")); v.Target {
		t.Fatalf("should not match")
	}
}

func TestScanTLSPayload_AllDomains(t *testing.T) {
	domain := "any.domain"
	sec := &Section{
		AllDomains: true,
		Exclude:    buildMatcher(),
	}
	v := ScanTLSPayload(sec, clientHello(domain))
	if !v.Target {
		t.Fatalf("AllDomains should force Target")
	}
	if string(v.TargetSNIPtr) != domain {
		t.Fatalf("wrong SNI: %q", v.TargetSNIPtr)
	}
}

func TestScanTLSPayload_IncludeAndExclude(t *testing.T) {
	domain := "good.com"

	sec := &Section{
		SNIs:    buildMatcher(domain),
		Exclude: buildMatcher(domain),
	}
	v := ScanTLSPayload(sec, clientHello(domain))
	if v.Target {
		t.Fatalf("include hit must be cancelled by exclude")
	}
}

func TestScanTLSPayload_MalformedTLS(t *testing.T) {
	sec := &Section{
		SNIs:    buildMatcher("x.com"),
		Exclude: buildMatcher(),
	}
	if v := ScanTLSPayload(sec, []byte{0x16}); v.Target {
		t.Fatalf("malformed record should never set Target")
	}
}
