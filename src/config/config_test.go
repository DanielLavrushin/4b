package config

import (
	"reflect"
	"testing"
)

// ───────────────────────────────────────────────────────────────
// NewSection
// ───────────────────────────────────────────────────────────────

func TestNewSection_CopiesDefaultsAndSetsID(t *testing.T) {
	sec := NewSection(7)

	// ID is applied
	if sec.ID != 7 {
		t.Fatalf("ID = %d, want 7", sec.ID)
	}
	// Deep‑copy, not alias, of DefaultSection
	if &DefaultSection == sec {
		t.Fatalf("NewSection returned pointer to DefaultSection; want copy")
	}
	// A field we know from DefaultSection should match
	if sec.FakingTTL != DefaultSection.FakingTTL ||
		sec.FragSNIReverse != DefaultSection.FragSNIReverse {
		t.Fatalf("fields not copied from DefaultSection")
	}
	// prev/next must be nil after reset
	if sec.prev != nil || sec.next != nil {
		t.Fatalf("prev/next should be nil")
	}
}

// ───────────────────────────────────────────────────────────────
// Sections() – list traversal
// ───────────────────────────────────────────────────────────────

func TestConfig_SectionsTraversal(t *testing.T) {
	// Build three linked sections
	c := Config{}
	a := NewSection(1)
	b := NewSection(2)
	c2 := NewSection(3)

	a.next, b.prev = b, a
	b.next, c2.prev = c2, b
	c.FirstSection, c.LastSection = a, c2

	gotIDs := []int{}
	for _, s := range c.Sections() {
		gotIDs = append(gotIDs, s.ID)
	}
	wantIDs := []int{1, 2, 3}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("Sections IDs %v, want %v", gotIDs, wantIDs)
	}
}

// ───────────────────────────────────────────────────────────────
// MatchesSNI
// ───────────────────────────────────────────────────────────────

func TestSection_MatchesSNI(t *testing.T) {
	sec := NewSection(0)
	sec.SNIDomains = []string{"example.com", "foo.bar"}
	sec.ExcludeSNIDomains = []string{"evil.example.com"}

	tests := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"www.example.com", true}, // suffix match
		{"foo.bar", true},
		{"evil.example.com", false},     // excluded exact
		{"sub.evil.example.com", false}, // excluded sub‑domain
		{"other.com", false},
	}

	for _, tc := range tests {
		if got := sec.MatchesSNI(tc.host); got != tc.want {
			t.Errorf("MatchesSNI(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}

	// AllDomains overrides everything
	sec.AllDomains = 1
	if !sec.MatchesSNI("whatever.tld") {
		t.Fatalf("AllDomains=1 should match any host")
	}
}

// ───────────────────────────────────────────────────────────────
// hexToBytes
// ───────────────────────────────────────────────────────────────

func TestHexToBytes(t *testing.T) {
	tests := []struct {
		in      string
		wantOut []byte
		wantErr bool
	}{
		{"", []byte{}, false},
		{"00ff10", []byte{0x00, 0xFF, 0x10}, false},
		{"0", nil, true},  // odd length
		{"zz", nil, true}, // non‑hex
	}

	for _, tc := range tests {
		got, err := hexToBytes(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("hexToBytes(%q) error=%v, wantErr=%v", tc.in, err, tc.wantErr)
		}
		if !tc.wantErr && !reflect.DeepEqual(got, tc.wantOut) {
			t.Errorf("hexToBytes(%q) = %#v, want %#v", tc.in, got, tc.wantOut)
		}
	}
}
