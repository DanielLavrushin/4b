package mangle

func IPVersion(pkt []byte) int {
	if len(pkt) < 1 { return 0 }
	switch pkt[0] >> 4 {
	case 4:
		return 4
	case 6:
		return 6
	default:
		return 0
	}
}