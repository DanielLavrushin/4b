package mangle

import (
	"encoding/binary"

	"github.com/daniellavrushin/b4/sni"
)

func processUDP(match func(string) bool, raw []byte, v6 bool) Verdict {
	ip4 := !v6
	ihl := 20
	off := 0
	if ip4 {
		if len(raw) < 28 {
			return VerdictAccept
		}
		if raw[9] != 17 {
			return VerdictAccept
		}
		ihl = int(raw[0]&0x0f) * 4
		off = ihl
	} else {
		if len(raw) < 48 {
			return VerdictAccept
		}
		if raw[6] != 17 {
			return VerdictAccept
		}
		off = 40
	}
	if len(raw) < off+8 {
		return VerdictAccept
	}
	plen := len(raw) - off - 8
	data := raw[off+8:]
	if plen <= 0 || len(data) == 0 {
		return VerdictAccept
	}
	host, ok := sni.ParseQUICClientHelloSNI(data)
	if !ok || host == "" {
		return VerdictAccept
	}
	if !match(host) {
		return VerdictAccept
	}
	if ip4 {
		for i := 0; i < defaultUDPFakeSeqLen; i++ {
			fp := buildFakeUDPv4(raw[:ihl], raw[off:off+8], defaultUDPFakeLen, defaultUDPFakingChecksum)
			if len(fp) != 0 {
				_ = sendRaw(fp)
			}
		}
	} else {
		for i := 0; i < defaultUDPFakeSeqLen; i++ {
			fp := buildFakeUDPv6(raw[:40], raw[off:off+8], defaultUDPFakeLen, defaultUDPFakingChecksum)
			if len(fp) != 0 {
				_ = sendRaw(fp)
			}
		}
	}
	return VerdictAccept
}

func buildFakeUDPv4(ip, udph []byte, dlen int, breakChecksum bool) []byte {
	if dlen < 0 {
		dlen = 0
	}
	seg := make([]byte, len(ip)+len(udph)+dlen)
	copy(seg, ip)
	copy(seg[len(ip):], udph)
	for i := 0; i < dlen; i++ {
		seg[len(ip)+len(udph)+i] = 0
	}
	binary.BigEndian.PutUint16(seg[2:4], uint16(len(seg)))
	u := seg[len(ip):]
	binary.BigEndian.PutUint16(u[4:6], uint16(len(udph)+dlen))
	u[6], u[7] = 0, 0
	check := udpChecksumIPv4(seg[:len(ip)], u, seg[len(ip)+len(udph):])
	if breakChecksum {
		check++
	}
	binary.BigEndian.PutUint16(u[6:8], check)
	seg[10], seg[11] = 0, 0
	putIPChecksum(seg[:len(ip)])
	return seg
}

func buildFakeUDPv6(ip6, udph []byte, dlen int, breakChecksum bool) []byte {
	seg := make([]byte, len(ip6)+len(udph)+dlen)
	copy(seg, ip6)
	copy(seg[len(ip6):], udph)
	for i := 0; i < dlen; i++ {
		seg[len(ip6)+len(udph)+i] = 0
	}
	binary.BigEndian.PutUint16(seg[len(ip6):len(ip6)+4], uint16(len(udph)+dlen))
	u := seg[len(ip6):]
	u[6], u[7] = 0, 0
	check := udpChecksumIPv6(seg[:len(ip6)], u, seg[len(ip6)+len(udph):])
	if breakChecksum {
		check++
	}
	binary.BigEndian.PutUint16(u[6:8], check)
	return seg
}
