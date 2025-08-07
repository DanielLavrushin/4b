package mangle

import "testing"

// ───────────────────────────────────────────────────────────────
// deterministic table‑driven test
// ───────────────────────────────────────────────────────────────
func TestIPVersion(t *testing.T) {
	tests := []struct {
		name string
		pkt  []byte
		want int
	}{
		{"IPv4 header byte 0x45", []byte{0x45, 0x00}, 4},
		{"IPv6 header byte 0x60", []byte{0x60, 0x00}, 6},
		{"garbage version → 0", []byte{0x10}, 0},
		{"empty slice → 0", nil, 0},
	}

	for _, tc := range tests {
		tc := tc // capture
		t.Run(tc.name, func(t *testing.T) {
			if got := IPVersion(tc.pkt); got != tc.want {
				t.Fatalf("IPVersion(%v) = %d, want %d", tc.pkt, got, tc.want)
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────
// optional fuzz test (Go 1.18+)
// run with: go test -fuzz=FuzzIPVersion -fuzztime=10s ./mangle
// ───────────────────────────────────────────────────────────────
func FuzzIPVersion(f *testing.F) {
	// seed corpora ─ deterministic examples
	f.Add([]byte{0x45})
	f.Add([]byte{0x60})
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		v := IPVersion(data)
		if v != 0 && v != 4 && v != 6 {
			t.Fatalf("invalid return %d for input %x", v, data)
		}
	})
}
