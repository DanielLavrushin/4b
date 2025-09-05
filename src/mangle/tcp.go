package mangle

import (
	"encoding/binary"
	"time"

	"github.com/daniellavrushin/b4/log"
)

func processTCP(match func(string) bool, raw []byte) Verdict {
	_, ip6, ihl, tcpOff, ok := locateTCP(raw)
	if !ok {
		return VerdictAccept
	}
	data := raw[tcpOff:]
	if len(data) == 0 {
		return VerdictContinue
	}
	if p, ok := findTLSClientHelloStart(data); ok {
		host, off, ln, ok := parseSNIAndOffset(data[p:])
		if !ok || host == "" {
			return VerdictContinue
		}
		if !match(host) {
			return VerdictContinue
		}
		if ip6 {
			return verdictTCPv6(raw, ihl, tcpOff, p, off, ln)
		}
		return verdictTCPv4(raw, ihl, tcpOff, p, off, ln)
	}
	return VerdictContinue
}

func verdictTCPv4(raw []byte, ihl, tcpOff, chStart, sniOff, sniLen int) Verdict {
	ip := raw[:ihl]
	tcph := raw[ihl:tcpOff]
	payload := raw[tcpOff:]

	fakeOnce := defaultFakeSNISeqLen
	for i := 0; i < fakeOnce; i++ {
		fp := buildFakeTLSv4(ip, tcph, uint32(defaultFakeSeqOffset))
		if len(fp) != 0 {
			_ = sendRaw(fp)
		}
	}
	log.Infof("INJECT TCP fake past_seq=%d", defaultFakeSeqOffset)

	pos := make([]int, 0, 2)
	if defaultFragSNIPos > 0 && len(payload) > defaultFragSNIPos {
		pos = append(pos, defaultFragSNIPos)
	}
	if defaultFragMiddleSNI && sniLen > 0 {
		mid := chStart + sniOff + sniLen/2
		if mid < len(payload) {
			if r := mid % 8; r != 0 {
				mid += 8 - r
				if mid >= len(payload) {
					mid = len(payload) - 1
				}
			}
			pos = append(pos, mid)
		}
	}
	if len(pos) == 0 {
		seg := buildTCPSegv4(ip, tcph, payload, 0, len(payload))
		if len(seg) != 0 {
			_ = sendRaw(seg)
			log.Infof("INJECT TCP split passthrough len=%d", len(payload))
			return VerdictDrop
		}
		return VerdictAccept
	}
	if len(pos) == 1 {
		a := clamp(pos[0], 1, len(payload)-1)
		s1 := buildTCPSegv4(ip, tcph, payload, 0, a)
		s2 := buildTCPSegv4Seq(ip, tcph, payload, a, len(payload), uint32(a))
		log.Infof("INJECT TCP split pos=%d reverse=%t", a, defaultFragSNIReverse)
		if defaultFragSNIReverse {
			if len(s2) != 0 {
				_ = sendRaw(s2)
			}
			if defaultSeg2Delay > 0 {
				time.Sleep(defaultSeg2Delay)
			}
			if len(s1) != 0 {
				_ = sendRaw(s1)
			}
		} else {
			if len(s1) != 0 {
				_ = sendRaw(s1)
			}
			if defaultSeg2Delay > 0 {
				time.Sleep(defaultSeg2Delay)
			}
			if len(s2) != 0 {
				_ = sendRaw(s2)
			}
		}
		return VerdictDrop
	}
	if pos[0] > pos[1] {
		pos[0], pos[1] = pos[1], pos[0]
	}
	a := clamp(pos[0], 1, len(payload)-2)
	b := clamp(pos[1], a+1, len(payload)-1)
	s1 := buildTCPSegv4(ip, tcph, payload, 0, a)
	s2 := buildTCPSegv4Seq(ip, tcph, payload, a, b, uint32(a))
	s3 := buildTCPSegv4Seq(ip, tcph, payload, b, len(payload), uint32(b))
	log.Infof("INJECT TCP split3 a=%d b=%d reverse=%t", a, b, defaultFragSNIReverse)
	if defaultFragSNIReverse {
		if len(s3) != 0 {
			_ = sendRaw(s3)
		}
		if defaultSeg2Delay > 0 {
			time.Sleep(defaultSeg2Delay)
		}
		if len(s2) != 0 {
			_ = sendRaw(s2)
		}
		if len(s1) != 0 {
			_ = sendRaw(s1)
		}
	} else {
		if len(s1) != 0 {
			_ = sendRaw(s1)
		}
		if defaultSeg2Delay > 0 {
			time.Sleep(defaultSeg2Delay)
		}
		if len(s2) != 0 {
			_ = sendRaw(s2)
		}
		if len(s3) != 0 {
			_ = sendRaw(s3)
		}
	}
	return VerdictDrop
}

func verdictTCPv6(raw []byte, ihl, tcpOff, chStart, sniOff, sniLen int) Verdict {
	return VerdictAccept
}

func findTLSClientHelloStart(b []byte) (int, bool) {
	for i := 0; i+6 < len(b); i++ {
		if b[i] != 0x16 {
			continue
		}
		if b[i+1] != 0x03 {
			continue
		}
		if b[i+5] == 0x01 {
			return i, true
		}
	}
	return 0, false
}

func parseSNIAndOffset(data []byte) (string, int, int, bool) {
	if len(data) < 11 {
		return "", 0, 0, false
	}
	if data[0] != 0x16 {
		return "", 0, 0, false
	}
	if data[5] != 0x01 {
		return "", 0, 0, false
	}
	hs := data[5:]
	if len(hs) < 4 {
		return "", 0, 0, false
	}
	msgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+msgLen > len(hs) {
		return "", 0, 0, false
	}
	p := hs[4:]
	if len(p) < 34 {
		return "", 0, 0, false
	}
	p = p[34:]
	if len(p) < 1 {
		return "", 0, 0, false
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen+2 {
		return "", 0, 0, false
	}
	p = p[sidLen:]
	cl := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if len(p) < cl+1 {
		return "", 0, 0, false
	}
	p = p[cl:]
	cml := int(p[0])
	p = p[1:]
	if len(p) < cml+2 {
		return "", 0, 0, false
	}
	p = p[cml:]
	extLen := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if len(p) < extLen {
		extLen = len(p)
	}
	q := p[:extLen]
	base := len(data) - len(q)
	for len(q) >= 4 {
		et := int(binary.BigEndian.Uint16(q[:2]))
		el := int(binary.BigEndian.Uint16(q[2:4]))
		q = q[4:]
		if el > len(q) {
			break
		}
		if et == 0 {
			if el < 5 {
				return "", 0, 0, false
			}
			lv := int(binary.BigEndian.Uint16(q[:2]))
			if 2+lv > el {
				return "", 0, 0, false
			}
			r := q[2 : 2+lv]
			if len(r) < 3 {
				return "", 0, 0, false
			}
			if r[0] != 0x00 {
				return "", 0, 0, false
			}
			hn := int(binary.BigEndian.Uint16(r[1:3]))
			if 3+hn > len(r) {
				return "", 0, 0, false
			}
			name := r[3 : 3+hn]
			off := base + 2 + 1 + 2
			return string(name), off, hn, true
		}
		q = q[el:]
		base += 4 + el
	}
	return "", 0, 0, false
}

func locateTCP(pkt []byte) (bool, bool, int, int, bool) {
	if len(pkt) < 1 {
		return false, false, 0, 0, false
	}
	v := pkt[0] >> 4
	if v == 4 {
		if len(pkt) < 20 {
			return true, false, 0, 0, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < ihl+20 {
			return true, false, 0, 0, false
		}
		if pkt[9] != 6 {
			return true, false, 0, 0, false
		}
		doff := (int(pkt[ihl+12]) >> 4) * 4
		return true, false, ihl, ihl + doff, true
	}
	if v == 6 {
		if len(pkt) < 40 {
			return false, true, 0, 0, false
		}
		next := int(pkt[6])
		off := 40
		for {
			if next == 6 {
				if len(pkt) < off+20 {
					return false, true, 0, 0, false
				}
				doff := (int(pkt[off+12]) >> 4) * 4
				return false, true, 40, off + doff, true
			}
			switch next {
			case 0:
				if len(pkt) < off+8 {
					return false, true, 0, 0, false
				}
				nn := int(pkt[off])
				if nn == 0 {
					return false, true, 0, 0, false
				}
				l := int(binary.BigEndian.Uint16(pkt[off+6 : off+8]))
				next = nn
				off += l
			case 43, 44, 51, 50, 60:
				if len(pkt) < off+8 {
					return false, true, 0, 0, false
				}
				nn := int(pkt[off])
				if nn == 0 {
					return false, true, 0, 0, false
				}
				l := int(binary.BigEndian.Uint16(pkt[off+6 : off+8]))
				next = nn
				off += l
			default:
				return false, true, 0, 0, false
			}
		}
	}
	return false, false, 0, 0, false
}

func buildTCPSegv4(ip, tcph, data []byte, a, b int) []byte {
	if a < 0 || b > len(data) || a >= b {
		return nil
	}
	seg := make([]byte, len(ip)+len(tcph)+(b-a))
	copy(seg, ip)
	copy(seg[len(ip):], tcph)
	copy(seg[len(ip)+len(tcph):], data[a:b])
	nip := seg[:len(ip)]
	ntcp := seg[len(ip) : len(ip)+len(tcph)]
	binary.BigEndian.PutUint16(nip[2:4], uint16(len(seg)))
	sum := tcpChecksumIPv4(nip, ntcp, seg[len(ip)+len(tcph):])
	binary.BigEndian.PutUint16(ntcp[16:18], sum)
	nip[10], nip[11] = 0, 0
	putIPChecksum(nip)
	return seg
}

func buildTCPSegv4Seq(ip, tcph, data []byte, a, b int, seqDelta uint32) []byte {
	seg := buildTCPSegv4(ip, tcph, data, a, b)
	if seg == nil {
		return nil
	}
	ntcp := seg[len(ip) : len(ip)+len(tcph)]
	seq := binary.BigEndian.Uint32(ntcp[4:8])
	binary.BigEndian.PutUint32(ntcp[4:8], seq+seqDelta)
	sum := tcpChecksumIPv4(seg[:len(ip)], ntcp, seg[len(ip)+len(tcph):])
	binary.BigEndian.PutUint16(ntcp[16:18], sum)
	return seg
}

func buildFakeTLSv4(ip, tcph []byte, past uint32) []byte {
	fakeLen := 560
	data := make([]byte, fakeLen)
	data[0] = 0x16
	data[1], data[2] = 0x03, 0x01
	data[3], data[4] = byte(fakeLen-5>>8), byte((fakeLen-5)&0xff)
	data[5] = 0x01
	copy(data[6:], make([]byte, fakeLen-6))
	seg := make([]byte, len(ip)+len(tcph)+len(data))
	copy(seg, ip)
	copy(seg[len(ip):], tcph)
	copy(seg[len(ip)+len(tcph):], data)
	ntcp := seg[len(ip) : len(ip)+len(tcph)]
	seq := binary.BigEndian.Uint32(ntcp[4:8])
	binary.BigEndian.PutUint32(ntcp[4:8], seq-uint32(past))
	binary.BigEndian.PutUint16(seg[2:4], uint16(len(seg)))
	sum := tcpChecksumIPv4(seg[:len(ip)], ntcp, data)
	binary.BigEndian.PutUint16(ntcp[16:18], sum)
	seg[10], seg[11] = 0, 0
	putIPChecksum(seg[:len(ip)])
	return seg
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
