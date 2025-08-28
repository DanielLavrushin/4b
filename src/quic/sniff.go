package quic

import (
	"errors"
)

// readVar decodes a QUIC variable‑length integer and returns (value, bytesRead).
// bytesRead==0 signals an error (truncated buffer).
func readVar(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	ln := 1 << (b[0] >> 6) // 0b00→1, 0b01→2, 0b10→4, 0b11→8
	if len(b) < ln {
		return 0, 0
	}
	v := uint64(b[0] & 0x3F)
	for i := 1; i < ln; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, ln
}

func cidLens(b []byte) (dstLen, srcLen int, off int, err error) {
	if len(b) < 1 {
		return 0, 0, 0, errors.New("truncated")
	}
	dstLen = int(b[0])
	off = 1
	if len(b) < off+dstLen+1 {
		return 0, 0, 0, errors.New("truncated")
	}
	off += dstLen
	srcLen = int(b[off])
	off++
	if len(b) < off+srcLen {
		return 0, 0, 0, errors.New("truncated")
	}
	off += srcLen
	return dstLen, srcLen, off, nil
}

// ExtractCrypto returns the first CRYPTO frame payload from an Initial packet.
func ExtractCrypto(initial []byte) ([]byte, bool) {
	if !IsInitial(initial) {
		return nil, false
	}
	// Skip: 1 flags, 4 version, 1 DCID len + DCID + SCID len + SCID
	_, _, skip, err := cidLens(initial[6:])
	if err != nil {
		return nil, false
	}
	payload := initial[6+skip:]

	for len(payload) > 0 {
		ftype, n := readVar(payload)
		if n == 0 {
			return nil, false
		}
		payload = payload[n:]

		// Only interested in CRYPTO (frame type 0x06)
		if ftype != 0x06 {
			// Skip: offset varint + length varint + length bytes
			off, m := readVar(payload)
			_ = off // offset ignored
			if m == 0 {
				return nil, false
			}
			length, k := readVar(payload[m:])
			if k == 0 {
				return nil, false
			}
			total := m + k + int(length)
			if len(payload) < total {
				return nil, false
			}
			payload = payload[total:]
			continue
		}

		// CRYPTO frame: <offset><length><data>
		_, m := readVar(payload) // offset varint (ignored)
		if m == 0 {
			return nil, false
		}
		length, k := readVar(payload[m:])
		if k == 0 {
			return nil, false
		}
		dataStart := m + k
		if len(payload) < dataStart+int(length) {
			return nil, false
		}
		return payload[dataStart : dataStart+int(length)], true
	}
	return nil, false
}
