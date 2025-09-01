package mangle

const (
	ip6NextHopByHop = 0
	ip6NextRouting  = 43
	ip6NextFragment = 44
	ip6NextAH       = 51
	ip6NextESP      = 50
	ip6NextDstOpts  = 60
	ip6NextNoNext   = 59
	ip6NextTCP      = 6
	ip6HeaderLen    = 40
)

func splitTCP(pkt []byte) ([]byte, bool) {
	if len(pkt) < 1 {
		return nil, false
	}
	ver := pkt[0] >> 4
	if ver == 4 {
		if len(pkt) < 20 {
			return nil, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+20 {
			return nil, false
		}
		if pkt[9] != 6 {
			return nil, false
		}
		ipPayload := pkt[ihl:]
		if len(ipPayload) < 20 {
			return nil, false
		}
		doff := int((ipPayload[12] >> 4) * 4)
		if doff < 20 || doff > len(ipPayload) {
			return nil, false
		}
		return ipPayload[doff:], true
	}
	if ver == 6 {
		if len(pkt) < ip6HeaderLen {
			return nil, false
		}
		next := pkt[6]
		off := ip6HeaderLen
		for {
			switch next {
			case ip6NextTCP:
				if len(pkt) < off+20 {
					return nil, false
				}
				doff := int((pkt[off+12] >> 4) * 4)
				if doff < 20 || off+doff > len(pkt) {
					return nil, false
				}
				return pkt[off+doff:], true
			case ip6NextNoNext:
				return nil, false
			case ip6NextHopByHop, ip6NextRouting, ip6NextDstOpts:
				if len(pkt) < off+2 {
					return nil, false
				}
				nn := pkt[off]
				extLen := int(pkt[off+1])
				l := (extLen + 1) * 8
				if l < 8 || len(pkt) < off+l {
					return nil, false
				}
				next = nn
				off += l
			case ip6NextFragment:
				if len(pkt) < off+8 {
					return nil, false
				}
				next = pkt[off]
				off += 8
			case ip6NextAH:
				if len(pkt) < off+2 {
					return nil, false
				}
				nn := pkt[off]
				pl := int(pkt[off+1])
				l := (pl + 2) * 4
				if l < 8 || len(pkt) < off+l {
					return nil, false
				}
				next = nn
				off += l
			case ip6NextESP:
				return nil, false
			default:
				return nil, false
			}
		}
	}
	return nil, false
}
