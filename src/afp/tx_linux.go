//go:build linux

package afp

import (
	"encoding/binary"
	"errors"

	"github.com/daniellavrushin/b4/log"
	"golang.org/x/sys/unix"
)

type Injector struct {
	fd4 int
	fd6 int
}

func NewInjector(mark int) (*Injector, error) {
	inj := &Injector{}
	// IPv4 raw (IPPROTO_RAW implies IP_HDRINCL semantics)
	fd4, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err == nil {
		_ = unix.SetsockoptInt(fd4, unix.SOL_SOCKET, unix.SO_MARK, mark)
		inj.fd4 = fd4
	} else {
		log.Errorf("raw v4 socket: %v", err)
	}

	// IPv6 raw
	fd6, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err == nil {
		_ = unix.SetsockoptInt(fd6, unix.SOL_SOCKET, unix.SO_MARK, mark)
		inj.fd6 = fd6
	} else {
		log.Errorf("raw v6 socket: %v", err)
	}

	if inj.fd4 == 0 && inj.fd6 == 0 {
		return nil, errors.New("no raw sockets")
	}
	return inj, nil
}

func (i *Injector) Close() {
	if i.fd4 != 0 {
		_ = unix.Close(i.fd4)
	}
	if i.fd6 != 0 {
		_ = unix.Close(i.fd6)
	}
}

// SendRaw takes a full L3 packet (IPv4 or IPv6, with transport header + data)
// and pushes it out via raw socket, like youtubeUnblock.
func (i *Injector) SendRaw(pkt []byte) error {
	if len(pkt) < 1 {
		return nil
	}
	ver := pkt[0] >> 4
	switch ver {
	case 4:
		if i.fd4 == 0 || len(pkt) < 20 {
			return nil
		}
		dst := pkt[16:20]
		sa := &unix.SockaddrInet4{Addr: [4]byte{dst[0], dst[1], dst[2], dst[3]}}
		// Expect IP header + payload provided by caller.
		return unix.Sendto(i.fd4, pkt, unix.MSG_DONTWAIT, sa)
	case 6:
		if i.fd6 == 0 || len(pkt) < 40 {
			return nil
		}
		var d [16]byte
		copy(d[:], pkt[24:40])
		sa := &unix.SockaddrInet6{Addr: d}
		// For v6 raw, kernel builds IPv6 header when protocol is IPPROTO_RAW
		// but here we still pass the complete L3 (works on modern kernels).
		return unix.Sendto(i.fd6, pkt, unix.MSG_DONTWAIT, sa)
	default:
		return nil
	}
}

// Utility (optional) – fix IPv4 header checksum if you modify headers
func FixIPv4Checksum(ip []byte) {
	ip[10], ip[11] = 0, 0
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	binary.BigEndian.PutUint16(ip[10:12], csum)
}
