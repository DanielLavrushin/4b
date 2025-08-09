// rawsock_bsd.go
//go:build freebsd || openbsd || darwin

package rawsock

import (
	"sync"

	"golang.org/x/sys/unix"
)

type Sender func([]byte) error

func New(mark uint32) (Sender, Sender, error) {
	open := func(family int) (int, error) {
		fd, err := unix.Socket(family, unix.SOCK_RAW, unix.IPPROTO_RAW)
		if err != nil {
			return -1, err
		}
		// No SO_MARK on *BSD.

		// For IPv4 we need to say we include the IP header.
		if family == unix.AF_INET {
			_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
		}
		// NOTE: IPv6 HDRINCL-style sending is not available in a compatible way,
		// and IPV6_HDRINCL is not defined in x/sys/unix here. We'll disable v6.
		return fd, nil
	}

	fd4, _ := open(unix.AF_INET)
	//fd6 := -1 // disable IPv6 sender on *BSD

	var mu4 sync.Mutex

	ip4Sender := func(pkt []byte) error {
		if fd4 < 0 {
			return unix.EINVAL
		}
		var sa unix.SockaddrInet4
		copy(sa.Addr[:], pkt[16:20]) // dst IPv4
		mu4.Lock()
		err := unix.Sendto(fd4, pkt, 0, &sa)
		mu4.Unlock()
		return err
	}

	// IPv6 not supported on *BSD in this raw mode
	ip6Sender := func(_ []byte) error {
		return unix.EPROTONOSUPPORT
	}

	return ip4Sender, ip6Sender, nil
}
