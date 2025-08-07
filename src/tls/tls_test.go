package tls

import (
	"crypto/rand"
	"testing"
)

// putUint16 appends a big‑endian uint16 to dst.
func putUint16(dst *[]byte, v uint16) {
	*dst = append(*dst, byte(v>>8), byte(v))
}

// buildClientHello returns the exact wire format that ExtractSNI expects.
// Only the fields the parser touches are populated; everything else is
// dummy data with correct length prefixes so offsets line up perfectly.
func buildClientHello(hosts [][]byte) []byte {
	// ---------- ClientHello body ------------------------------------------
	body := make([]byte, 0, 128)

	// legacy_version (TLS 1.2)
	body = append(body, 0x03, 0x03)

	// random (32 bytes)
	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)
	body = append(body, rnd...)

	// session‑id (length 0)
	body = append(body, 0x00)

	// cipher‑suites (TLS_AES_128_GCM_SHA256)
	putUint16(&body, 2)
	body = append(body, 0x13, 0x01)

	// compression methods (null)
	body = append(body, 0x01, 0x00)

	// ---------- extensions -------------------------------------------------
	ext := make([]byte, 0, 64)
	if len(hosts) > 0 {
		// Build SNI list
		sniList := make([]byte, 0, 32)
		for _, h := range hosts {
			sniList = append(sniList, 0x00) // name_type = host_name
			putUint16(&sniList, uint16(len(h)))
			sniList = append(sniList, h...)
		}

		// Prefix list length
		sni := make([]byte, 0, len(sniList)+2)
		putUint16(&sni, uint16(len(sniList)))
		sni = append(sni, sniList...)

		// Extension header
		putUint16(&ext, tlsExtServerName)
		putUint16(&ext, uint16(len(sni)))
		ext = append(ext, sni...)
	}
	// Wrap extensions with total length
	extensions := make([]byte, 0, len(ext)+2)
	putUint16(&extensions, uint16(len(ext)))
	extensions = append(extensions, ext...)

	body = append(body, extensions...)

	// ---------- Handshake layer -------------------------------------------
	handshake := make([]byte, 0, len(body)+4)
	handshake = append(handshake, tlsHandshakeClientHello)
	handshake = append(handshake,
		byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	// ---------- TLS record header -----------------------------------------
	// NB: the header shape follows the odd, historical layout that the C
	// version parsed (skip 1 byte, legacyVersion uint16, length uint16).
	rec := make([]byte, 0, len(handshake)+6)
	rec = append(rec, tlsContentTypeHandshake) // ContentType
	rec = append(rec, 0x03)                    // skipped byte
	putUint16(&rec, 0x0303)                    // “legacyVersion”
	putUint16(&rec, uint16(len(handshake)))    // record length
	rec = append(rec, handshake...)

	return rec
}

func TestExtractSNI(t *testing.T) {
	// --- happy path -------------------------------------------------------
	valid := buildClientHello([][]byte{[]byte("example.com")})
	got, err := ExtractSNI(valid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "example.com" {
		t.Fatalf("want example.com, got %q", got)
	}

	// --- no SNI extension -------------------------------------------------
	t.Run("no-SNI", func(t *testing.T) {
		pkt := buildClientHello(nil)
		if _, err := ExtractSNI(pkt); err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	// --- wrong ContentType -----------------------------------------------
	t.Run("wrong-content-type", func(t *testing.T) {
		pkt := append([]byte(nil), valid...)
		pkt[0] = 0x14 // TLS_ChangeCipherSpec
		if _, err := ExtractSNI(pkt); err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	// --- multiple host names – first wins ---------------------------------
	t.Run("multiple-names-first-wins", func(t *testing.T) {
		pkt := buildClientHello([][]byte{
			[]byte("first.test"),
			[]byte("second.test"),
		})
		got, err := ExtractSNI(pkt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != "first.test" {
			t.Fatalf("want first.test, got %q", got)
		}
	})
}
