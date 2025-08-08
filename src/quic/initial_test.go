package quic

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func encVar(x uint64) []byte {
	switch {
	case x < 1<<6:
		return []byte{byte(x)} // 00|xxxxxx
	case x < 1<<14:
		// 01|xxxxxxxx xxxxxxxx
		b := []byte{0, 0}
		b[0] = 0x40 | byte(x>>8)
		b[1] = byte(x)
		return b
	case x < 1<<30:
		b := []byte{0, 0, 0, 0}
		b[0] = 0x80 | byte(x>>24)
		b[1] = byte(x >> 16)
		b[2] = byte(x >> 8)
		b[3] = byte(x)
		return b
	default:
		b := []byte{0, 0, 0, 0, 0, 0, 0, 0}
		b[0] = 0xC0 | byte(x>>56)
		b[1] = byte(x >> 48)
		b[2] = byte(x >> 40)
		b[3] = byte(x >> 32)
		b[4] = byte(x >> 24)
		b[5] = byte(x >> 16)
		b[6] = byte(x >> 8)
		b[7] = byte(x)
		return b
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hexEq(t *testing.T, got []byte, wantHex string) {
	if hex.EncodeToString(got) != wantHex {
		t.Fatalf("\n got:  %s\n want: %s", hex.EncodeToString(got), wantHex)
	}
}

// Build a valid QUIC v1 Initial carrying a single CRYPTO frame with 'cryptoData'.
// We perform *real* AEAD encryption and header protection so DecryptInitial must
// fully reverse it.
func buildV1InitialPacket(dcid, scid []byte, pn uint32, cryptoData []byte) []byte {
	// 1) Plaintext QUIC payload: CRYPTO frame (type=0x06, off=0, len=|data|, data)
	var plain []byte
	plain = append(plain, encVar(0x06)...) // CRYPTO
	plain = append(plain, encVar(0)...)    // offset=0
	plain = append(plain, encVar(uint64(len(cryptoData)))...)
	plain = append(plain, cryptoData...)

	// 2) Derive Initial keys (v1)
	hp, aead, iv, err := deriveInitial(dcid, versionV1)
	if err != nil {
		panic(err)
	}

	// 3) Construct long-header up to PN (unmasked PN)
	// First byte: Long Header (bit7=1), Fixed bit (bit6=1), Type=Initial (bits 5..4=00), low2=pnLen-1
	pnLen := 2
	first := byte(0xC0 | byte(pnLen-1))
	hdr := []byte{first, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(hdr[1:], versionV1)

	// DCID Len + DCID
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)

	// SCID Len + SCID
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)

	// Token length=0
	hdr = append(hdr, encVar(0)...)

	// Length = pnLen + ciphertextLen + tagLen. CiphertextLen = len(plain).
	length := uint64(pnLen + len(plain) + 16)
	hdr = append(hdr, encVar(length)...)

	pnOff := len(hdr)
	// Append PN (truncated big-endian)
	hdr = append(hdr, byte(pn>>8), byte(pn))

	// 4) AEAD encrypt: AAD=hdr (through PN), Nonce=iv XOR PN
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	nonce[len(nonce)-2] ^= byte(pn >> 8)
	nonce[len(nonce)-1] ^= byte(pn)

	ct := aead.Seal(nil, nonce, plain, hdr)

	// 5) Apply header protection: sample at pnOff + 4
	pkt := append(append([]byte{}, hdr...), ct...)
	sampleStart := pnOff + 4
	maskIn := pkt[sampleStart : sampleStart+16]
	var mask [16]byte
	hp.Encrypt(mask[:], maskIn)

	// Mask first byte (low 4 bits for long header) and PN bytes
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}

func TestV1DerivationVectors(t *testing.T) {
	dcid := mustHex("8394c8f03e515708")

	// HKDF-Extract(saltV1, dcid)
	prk := hkdfExtractSHA256(saltV1, dcid)
	hexEq(t, prk, "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44") // RFC 9001 A.1

	// client_in → client secret
	client, err := hkdfExpandLabel(prk, "client in", 32)
	if err != nil {
		t.Fatal(err)
	}
	hexEq(t, client, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")

	// keys/iv/hp for v1
	key, err := hkdfExpandLabel(client, "quic key", 16)
	if err != nil {
		t.Fatal(err)
	}
	iv, err := hkdfExpandLabel(client, "quic iv", 12)
	if err != nil {
		t.Fatal(err)
	}
	hp, err := hkdfExpandLabel(client, "quic hp", 16)
	if err != nil {
		t.Fatal(err)
	}

	hexEq(t, key, "1f369613dd76d5467730efcbe3b1a22d")
	hexEq(t, iv, "fa044b2f42a3fd3b46fb255c")
	hexEq(t, hp, "9f50449e04a0e810283a1e9933adedd2")
}

func TestV2IsInitialMapping(t *testing.T) {
	// Minimal long header: |1|long|type|..|, version=v2, DCID/SCID lens = 0
	b := make([]byte, 7)
	b[0] = 0x80 | (0x01 << 4) // long header + type=01 (Initial in v2)
	binary.BigEndian.PutUint32(b[1:5], versionV2)
	// dcid_len=0, scid_len=0
	// b[5]=0, b[6]=0 (already zero)

	if !IsInitial(b) {
		t.Fatalf("v2 Initial mapping failed (expected true)")
	}
	// Retry in v2 is 00 → not Initial
	b[0] = 0x80 | (0x00 << 4)
	if IsInitial(b) {
		t.Fatalf("v2 Retry misclassified as Initial")
	}
}

func TestDeriveInitial_V1vsV2_DifferentKeys(t *testing.T) {
	dcid := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	_, aead1, iv1, err1 := deriveInitial(dcid, versionV1)
	_, aead2, iv2, err2 := deriveInitial(dcid, versionV2)
	if err1 != nil || err2 != nil {
		t.Fatalf("derive failed: v1 err=%v v2 err=%v", err1, err2)
	}
	// GCM uses the same key for both AEAD and HP branches internally, but iv differs across versions due to salt/labels.
	if string(iv1) == string(iv2) {
		t.Fatalf("v1 and v2 produced identical IV; expected difference")
	}
	// also ensure both AEADs exist so code paths are exercised
	if aead1 == nil || aead2 == nil {
		t.Fatalf("nil AEAD")
	}
}

func TestInitialDecrypt_AssembleCrypto_RoundTrip(t *testing.T) {
	dcid := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	scid := []byte{9, 9, 9, 9}
	pn := uint32(0x1234)

	// Embed our "SNI" bytes inside the CRYPTO payload (we're not parsing TLS here).
	cryptoData := []byte("....example.com....")
	packet := buildV1InitialPacket(dcid, scid, pn, cryptoData)

	plain, ok := DecryptInitial(dcid, packet)
	if !ok {
		t.Fatalf("DecryptInitial failed")
	}

	out, ok := AssembleCrypto(plain)
	if !ok {
		t.Fatalf("AssembleCrypto failed")
	}
	if !bytes.Contains(out, cryptoData) {
		t.Fatalf("CRYPTO stream mismatch: got=%x … want to contain=%x", out, cryptoData)
	}
}

func TestDecryptInitial_DoesNotMutateInput(t *testing.T) {
	in := []byte{0x80, 0, 0, 0, versionV1, 0, 0} // minimal long-ish; decrypt likely fails
	dcid := []byte{0x01, 0x02, 0x03}
	cp := append([]byte(nil), in...)
	_, _ = DecryptInitial(dcid, in)
	if !bytes.Equal(in, cp) {
		t.Fatalf("DecryptInitial mutated input")
	}
}
