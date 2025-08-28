package quic

func ParseDCID(b []byte) []byte {
	if len(b) < 7 || b[0]&0x80 == 0 {
		return nil
	}
	off := 1 + 4
	dlen := int(b[off])
	off++
	if len(b) < off+dlen {
		return nil
	}
	return b[off : off+dlen]
}
