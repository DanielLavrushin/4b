package quic

import (
	"bytes"
	"testing"
)

/* ---------- small helpers ---------- */

// encodeVar encodes v (< 64) as a 1-byte QUIC varint.
func encodeVar(v byte) []byte { return []byte{v} }

// initialPkt builds the tiniest “Initial” packet that the sniff logic
// understands: 1-byte flags | 4-byte version | 0-len DCID | 0-len SCID |
// <frames>.  There is *no* packet-number or length field because
// ExtractCrypto never looks at them in this migration layer.
func initialPkt(version uint32, frames []byte) []byte {
	p := []byte{
		0x80, // flags (long hdr, Initial)
		byte(version >> 24), byte(version >> 16),
		byte(version >> 8), byte(version), // version
		0x00, // <--- gap the parser expects
		0x00, // DCID length = 0
		0x00, // SCID length = 0
	}
	return append(p, frames...)
}

/* ---------- readVar tests ---------- */

func TestReadVar(t *testing.T) {
	val, n := readVar([]byte{0x25})
	if val != 0x25 || n != 1 {
		t.Fatalf("single-byte varint failed: got (%d,%d)", val, n)
	}
	_, n = readVar([]byte{0x40}) // wants 2-byte integer but buffer too short
	if n != 0 {
		t.Fatalf("truncated varint should give n==0")
	}
}

/* ---------- IsInitial tests ---------- */

func TestIsInitial(t *testing.T) {
	okPkt := initialPkt(0x00000001, nil)
	if !IsInitial(okPkt) {
		t.Fatalf("expected IsInitial==true")
	}
	if IsInitial([]byte{0x00}) { // short header
		t.Fatalf("short header mis-detected as Initial")
	}
}

/* ---------- cidLens tests ---------- */

func TestCidLens(t *testing.T) {
	dst, src, off, err := cidLens([]byte{0x02, 0xaa, 0xbb, 0x01, 0xcc})
	if err != nil || dst != 2 || src != 1 || off != 5 { // <- expect 5
		t.Fatalf("cidLens wrong result: dst=%d src=%d off=%d err=%v", dst, src, off, err)
	}
	if _, _, _, err := cidLens([]byte{0x02}); err == nil {
		t.Fatalf("cidLens should fail on truncated buffer")
	}
}

/* ---------- ExtractCrypto tests ---------- */

func TestExtractCrypto(t *testing.T) {
	// --- build a CRYPTO frame -------------------------------------------
	data := []byte("hello")
	frame := append([]byte{0x06}, encodeVar(0x00)...)
	frame = append(frame, encodeVar(byte(len(data)))...)
	frame = append(frame, data...)

	// --- wrap into Initial packet ----------------------------------------
	pkt := initialPkt(0x00000001, frame)

	// --- happy path ------------------------------------------------------
	out, ok := ExtractCrypto(pkt)
	if !ok {
		t.Fatalf("ExtractCrypto returned ok=false")
	}
	if !bytes.Equal(out, data) {
		t.Fatalf("payload mismatch: got %q want %q", out, data)
	}

	// --- non-Initial packet ---------------------------------------------
	if _, ok := ExtractCrypto([]byte{0x00}); ok {
		t.Fatalf("should reject non-Initial packet")
	}

	// --- Initial with no CRYPTO frame -----------------------------------
	noCrypto := initialPkt(0x00000001, encodeVar(0x00)) // PADDING frame
	if _, ok := ExtractCrypto(noCrypto); ok {
		t.Fatalf("should fail when CRYPTO frame absent")
	}
}
