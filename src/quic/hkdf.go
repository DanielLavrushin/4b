package quic

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

func hkdfExpandLabel(secret []byte, label string, outLen int) ([]byte, error) {
	fullLabel := "tls13 " + label              // prepend mandatory prefix
	info := make([]byte, 2+1+len(fullLabel)+1) // 2-byte len, 1-byte lblLen, label, 1-byte ctxLen (zero)

	info[0] = byte(outLen >> 8)    // Length (MSB)
	info[1] = byte(outLen)         // Length (LSB)
	info[2] = byte(len(fullLabel)) // Label length
	copy(info[3:], fullLabel)      // Label
	// final zero byte is already 0 (context length = 0)

	r := hkdf.Expand(sha256.New, secret, info) // io.Reader
	out := make([]byte, outLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}
