package quic

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors: RFC 9001 A.5 “ChaCha20‑Poly1305 Short Header Packet”
// secret  = 9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b
// key     = c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8
// iv      = e0459b3474bdd0e44a41c144
// hp      = 25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4
//
// :contentReference[oaicite:0]{index=0}
func TestHKDFExpandLabel_RFC9001Vectors(t *testing.T) {
	secret, _ := hex.DecodeString(
		"9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")

	cases := []struct {
		label string
		size  int
		want  string // hex
	}{
		{"quic key", 32,
			"c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"},
		{"quic iv", 12,
			"e0459b3474bdd0e44a41c144"},
		{"quic hp", 32,
			"25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"},
	}

	for _, tc := range cases {
		got, err := hkdfExpandLabel(secret, tc.label, tc.size)
		if err != nil {
			t.Fatalf("hkdfExpandLabel(%q) returned error: %v", tc.label, err)
		}
		wantBytes, _ := hex.DecodeString(tc.want)
		if !bytes.Equal(got, wantBytes) {
			t.Errorf("%q mismatch:\n got  %x\n want %s",
				tc.label, got, tc.want)
		}
	}
}
