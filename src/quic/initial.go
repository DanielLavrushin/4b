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

func DecryptInitial(dcid, packet []byte) ([]byte, bool) {
	if len(packet) < 7 || packet[0]&0x80 == 0 {
		return nil, false
	} // long header
	ver := binary.BigEndian.Uint32(packet[1:5])
	hp, aead, iv, err := deriveInitial(dcid, ver)
	if err != nil {
		return nil, false
	}

	// flags(1) + version(4)
	off := 1 + 4

	// DCID Len + DCID
	if len(packet) < off+1 {
		return nil, false
	}
	dlen := int(packet[off])
	off++
	if len(packet) < off+dlen+1 {
		return nil, false
	}
	off += dlen

	// SCID Len + SCID
	slen := int(packet[off])
	off++
	if len(packet) < off+slen {
		return nil, false
	}
	off += slen

	// Token Length (varint) + Token
	tlen, n := readVar(packet[off:])
	if n == 0 || len(packet) < off+n+int(tlen) {
		return nil, false
	}
	off += n + int(tlen)

	// Length (varint)
	_, m := readVar(packet[off:])
	if m == 0 {
		return nil, false
	}
	pnOffset := off + m

	// RFC 9001 §5.4.2: sample starts 4 bytes after pn_offset
	if pnOffset+4+16 > len(packet) {
		return nil, false
	}
	sample := packet[pnOffset+4 : pnOffset+4+16]

	mask := make([]byte, 16)
	hp.Encrypt(mask, sample)

	// unmask header + pn
	if packet[0]&0x80 != 0 {
		packet[0] ^= mask[0] & 0x0f
	} else {
		packet[0] ^= mask[0] & 0x1f
	}
	pnLen := int((packet[0] & 0x03) + 1)
	for i := 0; i < pnLen; i++ {
		packet[pnOffset+i] ^= mask[i+1]
	}

	// build nonce = iv XOR pn
	for i := 0; i < pnLen; i++ {
		iv[ivSize-pnLen+i] ^= packet[pnOffset+i]
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

// AssembleCrypto walks a decrypted Initial payload and reconstructs
// the TLS handshake byte stream from CRYPTO frames (type 0x06).
// It tolerates PADDING (0x00) and stops on unknown frames.
func AssembleCrypto(plain []byte) ([]byte, bool) {
	buf := make([]byte, 16384)
	payload := plain
	for len(payload) > 0 {
		ftype, n := readVar(payload)
		if n == 0 {
			return nil, false
		}
		payload = payload[n:]
		switch ftype {
		case 0x00: // PADDING
			continue
		case 0x01: // PING (tolerate like C)
			continue
		case 0x06: // CRYPTO
			off, m := readVar(payload)
			if m == 0 {
				return nil, false
			}
			l, k := readVar(payload[m:])
			if k == 0 {
				return nil, false
			}
			dataStart := m + k
			if len(payload) < dataStart+int(l) {
				return nil, false
			}
			end := int(off) + int(l)
			if end > len(buf) {
				nb := make([]byte, end)
				copy(nb, buf)
				buf = nb
			}
			copy(buf[int(off):end], payload[dataStart:dataStart+int(l)])
			payload = payload[dataStart+int(l):]
		default:
			return buf, true
		}
	}
	return buf, true
}
