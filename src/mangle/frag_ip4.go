package mangle

import (
	"encoding/binary"
	"errors"

	"github.com/daniellavrushin/4b/utils"
)

// ip4Frag splits an IPv4 packet into two fragments at an 8-byte–aligned
// position inside the IP *payload* (ie. after the IP header).
//
// The caller guarantees:
//   - pkt is a full IPv4 datagram with no options (20-byte header)
//   - fragOffset is >0, <payloadLen, and a multiple of 8.
//
// Returned slices are freshly allocated and ready to send via a raw socket.
func ip4Frag(pkt []byte, fragOffset int) (first, second []byte, err error) {
	const ipHdrLen = 20
	if len(pkt) < ipHdrLen {
		return nil, nil, errors.New("ip4frag: packet too short")
	}
	hdr := make([]byte, ipHdrLen) // local working copy
	copy(hdr, pkt[:ipHdrLen])

	totalLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if totalLen != len(pkt) {
		return nil, nil, errors.New("ip4frag: inconsistent length")
	}
	payload := pkt[ipHdrLen:]
	if fragOffset <= 0 || fragOffset >= len(payload) || fragOffset%8 != 0 {
		return nil, nil, errors.New("ip4frag: bad offset")
	}

	// Common header fields we reuse
	id := binary.BigEndian.Uint16(hdr[4:6])
	ttl := hdr[8]
	proto := hdr[9]
	src := hdr[12:16]
	dst := hdr[16:20]

	build := func(pl []byte, moreFrags bool, offWords uint16) []byte {
		out := make([]byte, ipHdrLen+len(pl))
		copy(out[:4], []byte{0x45, 0}) // ver+ihl, TOS=0
		binary.BigEndian.PutUint16(out[2:4], uint16(ipHdrLen+len(pl)))
		binary.BigEndian.PutUint16(out[4:6], id)

		// Flags+offset: bit 13 = MF (more fragments)
		foVal := offWords & 0x1fff
		if moreFrags {
			foVal |= 0x2000
		}
		binary.BigEndian.PutUint16(out[6:8], foVal)

		out[8] = ttl
		out[9] = proto
		copy(out[12:16], src)
		copy(out[16:20], dst)

		// payload
		copy(out[ipHdrLen:], pl)

		// checksum
		binary.BigEndian.PutUint16(out[10:12], 0)
		cs := utils.IpChecksum(out[:ipHdrLen])
		binary.BigEndian.PutUint16(out[10:12], cs)
		return out
	}

	first = build(payload[:fragOffset], true, 0)
	second = build(payload[fragOffset:], false, uint16(fragOffset/8))
	return
}
