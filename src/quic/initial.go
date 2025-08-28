package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	secretSize = 32
	keySize    = 16
	ivSize     = 12
)

var saltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
var saltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}

const (
	versionV1 = 0x00000001
	versionV2 = 0x6b3343cf
)

const (
	longHdrBit = 0x80
)

func IsInitial(b []byte) bool {
	if len(b) < 7 || b[0]&longHdrBit == 0 { // short header or tiny packet
		return false
	}
	ptype := (b[0] & 0x30) >> 4 // bits 4–5 (version-specific meaning)
	ver := binary.BigEndian.Uint32(b[1:5])
	switch ver {
	case versionV1:
		// v1: Initial = 0b00
		return ptype == 0x00
	case versionV2:
		// RFC 9369 §3.2: v2 long-header mapping:
		// Initial=0b01, 0-RTT=0b10, Handshake=0b11, Retry=0b00
		// Normalize: treat 0b01 as Initial
		return ptype == 0x01
	default:
		return false
	}
}

func DecryptInitial(dcid, packet []byte) ([]byte, bool) {
	if len(packet) < 7 || packet[0]&0x80 == 0 {
		return nil, false
	}
	ver := binary.BigEndian.Uint32(packet[1:5])
	hp, aead, iv, err := deriveInitial(dcid, ver)
	if err != nil {
		return nil, false
	}

	// flags+ver
	off := 1 + 4

	// DCID len + DCID
	if len(packet) < off+1 {
		return nil, false
	}
	dlen := int(packet[off])
	off++
	if len(packet) < off+dlen+1 {
		return nil, false
	}
	off += dlen

	// SCID len + SCID
	slen := int(packet[off])
	off++
	if len(packet) < off+slen {
		return nil, false
	}
	off += slen

	// Token (varint + bytes)
	tlen, n := readVar(packet[off:])
	if n == 0 || len(packet) < off+n+int(tlen) {
		return nil, false
	}
	off += n + int(tlen)

	// Length (varint) -> PN offset
	_, m := readVar(packet[off:])
	if m == 0 {
		return nil, false
	}
	pnOff := off + m

	// HP sample (pnOff + 4)
	if pnOff+4+16 > len(packet) {
		return nil, false
	}
	var sample [16]byte
	copy(sample[:], packet[pnOff+4:pnOff+4+16])

	var mask [16]byte
	hp.Encrypt(mask[:], sample[:])

	// Unmasked first byte (long header: low 4 bits masked)
	first := packet[0] ^ (mask[0] & 0x0f)
	pnLen := int((first & 0x03) + 1)
	if pnOff+pnLen > len(packet) {
		return nil, false
	}

	// Unmasked PN bytes (don’t write back)
	var pnBytes [4]byte
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = packet[pnOff+i] ^ mask[1+i]
	}
	// Numeric PN (for nonce)
	var pn uint64
	for i := 0; i < pnLen; i++ {
		pn = (pn << 8) | uint64(pnBytes[i])
	}

	// Build AAD = header with first byte & PN unmasked, everything else identical
	aad := make([]byte, pnOff+pnLen)
	copy(aad, packet[:pnOff])
	aad[0] = first
	copy(aad[pnOff:], pnBytes[:pnLen])

	// Nonce = iv XOR pn (into a copy so we don’t mutate iv)
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < pnLen; i++ {
		nonce[len(nonce)-pnLen+i] ^= pnBytes[i]
	}

	// Ciphertext (incl. tag) follows PN
	ct := packet[pnOff+pnLen:]
	plain, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, false
	}
	return plain, true
}

func deriveInitial(dcid []byte, version uint32) (cipher.Block, cipher.AEAD, []byte, error) {
	var salt []byte

	labelPrefix := "quic"

	switch version {
	case versionV1:
		labelPrefix = "quic"
		salt = saltV1
	case versionV2:
		salt = saltV2
		labelPrefix = "quicv2"
	default:
		return nil, nil, nil, errors.New("unknown version")
	}

	// --- Step 1: initial_secret = HKDF-Extract(salt, dcid)
	secret := hkdfExtractSHA256(salt, dcid)

	client, err := hkdfExpandLabel(secret, "client in", secretSize)
	if err != nil {
		return nil, nil, nil, err
	}

	// --- Step 2: derive key/iv/hp with the *labelled* expand
	key, err := hkdfExpandLabel(client, labelPrefix+" key", keySize)
	if err != nil {
		return nil, nil, nil, err
	}
	iv, err := hkdfExpandLabel(client, labelPrefix+" iv", ivSize)
	if err != nil {
		return nil, nil, nil, err
	}
	hpkey, err := hkdfExpandLabel(client, labelPrefix+" hp", keySize)
	if err != nil {
		return nil, nil, nil, err
	}
	// --- Step 3: build ciphers
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}

	hp, err := aes.NewCipher(hpkey)
	if err != nil {
		return nil, nil, nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}

	return hp, aead, iv, nil
}

func hkdfExtractSHA256(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	_, _ = m.Write(ikm)
	return m.Sum(nil)
}
