package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	secretSize = 32
	keySize    = 16
	ivSize     = 12
)

var saltV1 = []byte{0xef, 0x4f, 0x4c, 0x67, 0x36, 0x00, 0x6b, 0x4d, 0x9c, 0xe7, 0x6c, 0x0f, 0xd9, 0x0e, 0xb3, 0x6b, 0xcf, 0x26, 0x6e, 0xbd}
var saltV2 = []byte{0xcd, 0x03, 0x4b, 0x7e, 0x4b, 0x06, 0xdb, 0x5e, 0xd9, 0x35, 0x9e, 0xfb, 0xc0, 0x28, 0x1d, 0xb0, 0xe7, 0x2a, 0xbb, 0xdd}

func DecryptInitial(dcid []byte, packet []byte) ([]byte, bool) {
	if !IsInitial(packet) {
		return nil, false
	}

	ver := binary.BigEndian.Uint32(packet[1:5])
	hp, aead, iv, err := deriveInitial(dcid, ver)
	if err != nil {
		return nil, false
	}
	if len(packet) < 7 {
		return nil, false
	}
	off := 1 + 4
	dcidLen := int(packet[5])
	off += 1 + dcidLen
	if len(packet) < off+1 {
		return nil, false
	}
	scidLen := int(packet[off])
	off += 1 + scidLen
	if len(packet) < off+1 {
		return nil, false
	}
	pnLen := int((packet[0] & 0x03) + 1)
	pnOffset := off
	sampleOffset := pnOffset + pnLen + 4
	if sampleOffset+16 > len(packet) {
		return nil, false
	}
	mask := make([]byte, 16)
	hp.Encrypt(mask, packet[sampleOffset:sampleOffset+16])
	packet[0] ^= mask[0] & 0x0f
	pnLen = int((packet[0] & 0x03) + 1)
	for i := 0; i < pnLen; i++ {
		packet[pnOffset+i] ^= mask[i+1]
	}
	pn := packet[pnOffset : pnOffset+pnLen]
	for i := 0; i < pnLen; i++ {
		iv[ivSize-pnLen+i] ^= pn[i]
	}
	associated := packet[:pnOffset+pnLen]
	ciphertext := packet[pnOffset+pnLen:]
	plain, err := aead.Open(nil, iv, ciphertext, associated)
	if err != nil {
		return nil, false
	}
	return plain, true
}

func deriveInitial(dcid []byte, version uint32) (cipher.Block, cipher.AEAD, []byte, error) {
	var salt []byte
	switch version {
	case 0x00000001:
		salt = saltV1
	case 0x709a50c4:
		salt = saltV2
	default:
		return nil, nil, nil, errors.New("unknown version")
	}

	// --- Step 1: initial secret = HKDF-Extract(salt, dcid)
	secret := make([]byte, secretSize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, dcid, salt, nil), secret); err != nil {
		return nil, nil, nil, err
	}

	client, err := hkdfExpandLabel(secret, "client in", secretSize)
	if err != nil {
		return nil, nil, nil, err
	}

	// --- Step 2: derive key/iv/hp with the *labelled* expand
	key, err := hkdfExpandLabel(client, "quic key", keySize)
	if err != nil {
		return nil, nil, nil, err
	}
	iv, err := hkdfExpandLabel(client, "quic iv", ivSize)
	if err != nil {
		return nil, nil, nil, err
	}
	hpkey, err := hkdfExpandLabel(client, "quic hp", keySize)
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
