package quic

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

/* ---------- helpers ---------- */

// buildInitial constructs a minimal encrypted Initial packet whose layout
// matches exactly what DecryptInitial expects:
//
// [0]      long-hdr first byte  (bits 0-1 carry pnLen)
// [1..4]   version
// [5]      dcidLen
// [...]    dcid
// [..]     scidLen (we use 0)
// [pn]     1-byte packet number (pnLen = 1)
// [cipher] ciphertext (AEAD-sealed)
//
//	└─ header protection applied
//
// It omits token/length/etc. because DecryptInitial never parses them.
func buildInitial(version uint32, payload []byte) ([]byte, []byte) {
	const pnLen = 1
	if len(payload) == 0 {
		payload = []byte("dummy payload …")
	}

	var dcid []byte
	for {
		// -------- derive a random DCID each attempt ----------------------
		dcid = make([]byte, 8)
		_, _ = rand.Read(dcid)

		// -------- keys ---------------------------------------------------
		hp, aead, iv, _ := deriveInitial(dcid, version)

		// -------- header (unprotected) -----------------------------------
		header := make([]byte, 0, 64)
		header = append(header, 0xc0) // first byte (pnLen=1)
		binary.BigEndian.PutUint32(header[len(header):len(header)+4], version)
		header = header[:len(header)+4]
		header = append(header, byte(len(dcid)))
		header = append(header, dcid...)
		header = append(header, 0x00) // scidLen = 0

		// -------- AEAD seal ----------------------------------------------
		pn := []byte{0x00}
		associated := append(append([]byte(nil), header...), pn...)

		nonce := append([]byte(nil), iv...)
		nonce[len(nonce)-1] ^= pn[0]

		ciphertext := aead.Seal(nil, nonce, payload, associated)

		// -------- header protection --------------------------------------
		sample := ciphertext[4 : 4+16]
		mask := make([]byte, 16)
		hp.Encrypt(mask, sample)

		if mask[0]&0x03 != 0 {
			// The mask would change PN-length bits → try another DCID.
			continue
		}

		protected := append([]byte(nil), header...)
		protected[0] ^= mask[0] & 0x0f
		protected = append(protected, pn...)
		protected[len(header)] ^= mask[1]

		return append(protected, ciphertext...), dcid
	}
}

/* ---------- tests ---------- */

func TestDecryptInitial_Success(t *testing.T) {
	tests := []struct {
		name    string
		version uint32
	}{
		{"v1", 0x00000001},
		{"v2", 0x709a50c4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dcid := make([]byte, 8)
			_, _ = rand.Read(dcid)
			want := []byte("hello-quic-initial")

			pkt, dcid := buildInitial(tc.version, want)
			got, ok := DecryptInitial(dcid, append([]byte(nil), pkt...))
			if !ok {
				t.Fatalf("DecryptInitial returned ok=false")
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("payload mismatch: got %q want %q", got, want)
			}
		})
	}
}

func TestDecryptInitial_BadInputs(t *testing.T) {
	dcid := []byte{0xaa, 0xbb}

	// --- unknown version --------------------------------------------------
	// 1. build a perfectly valid v1 packet
	validPkt, dcid := buildInitial(0x00000001, nil)
	// 2. overwrite the version field (bytes 1..4) with an unsupported value
	binary.BigEndian.PutUint32(validPkt[1:5], 0x11223344) // unknown version
	if _, ok := DecryptInitial(dcid, validPkt); ok {
		t.Fatalf("expected failure on unknown version")
	}

	// --- truncated packet -------------------------------------------------
	shortPkt := []byte{0xc0}
	if _, ok := DecryptInitial(dcid, shortPkt); ok {
		t.Fatalf("expected failure on short packet")
	}
}
