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
	var labelIn, labelKey, labelIV, labelHP []byte

	switch version {
	case 0x00000001:
		salt = saltV1
		labelIn = []byte("tls13 client in\x00")
		labelKey = []byte("tls13 quic key\x00")
		labelIV = []byte("tls13 quic iv\x00")
		labelHP = []byte("tls13 quic hp\x00")
	case 0x709a50c4:
		salt = saltV2
		labelIn = []byte("tls13 client in\x00")
		labelKey = []byte("tls13 quicv2 key\x00")
		labelIV = []byte("tls13 quicv2 iv\x00")
		labelHP = []byte("tls13 quicv2 hp\x00")
	default:
		return nil, nil, nil, errors.New("unknown version")
	}

	h := hkdf.New(sha256.New, dcid, salt, labelIn)
	secret := make([]byte, secretSize)
	if _, err := io.ReadFull(h, secret); err != nil {
		return nil, nil, nil, err
	}
	prk := hkdf.New(sha256.New, secret, nil, labelKey)
	key := make([]byte, keySize)
	if _, err := io.ReadFull(prk, key); err != nil {
		return nil, nil, nil, err
	}
	prk = hkdf.New(sha256.New, secret, nil, labelIV)
	iv := make([]byte, ivSize)
	if _, err := io.ReadFull(prk, iv); err != nil {
		return nil, nil, nil, err
	}
	prk = hkdf.New(sha256.New, secret, nil, labelHP)
	hpkey := make([]byte, keySize)
	if _, err := io.ReadFull(prk, hpkey); err != nil {
		return nil, nil, nil, err
	}
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
