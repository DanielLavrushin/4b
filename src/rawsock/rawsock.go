package rawsock

import (
	"sync"

	"golang.org/x/sys/unix"
)

type Sender func(pkt []byte) error

// New returns ipv4Sender, ipv6Sender (either may be nil if open failed)
func New(mark uint32) (Sender, Sender, error) {
	open := func(family int) (int, error) {
		fd, err := unix.Socket(family, unix.SOCK_RAW, unix.IPPROTO_RAW)
		if err != nil {
			return -1, err
		}
		if mark != 0 {
			if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(mark)); err != nil {
				_ = unix.Close(fd)
				return -1, err
			}
		}
		return fd, nil
	}

	fd4, _ := open(unix.AF_INET)
	fd6, _ := open(unix.AF_INET6)

	var mu4, mu6 sync.Mutex

	ip4Sender := func(pkt []byte) error {
		if fd4 < 0 { return unix.EINVAL }
		var sa unix.SockaddrInet4
		copy(sa.Addr[:], pkt[16:20]) // dst IP
		mu4.Lock(); err := unix.Sendto(fd4, pkt, 0, &sa); mu4.Unlock()
		return err
	}
	ip6Sender := func(pkt []byte) error {
		if fd6 < 0 { return unix.EINVAL }
		var sa unix.SockaddrInet6
		copy(sa.Addr[:], pkt[24:40])
		mu6.Lock(); err := unix.Sendto(fd6, pkt, 0, &sa); mu6.Unlock()
		return err
	}

	return ip4Sender, ip6Sender, nil
}
