package mangle

import (
	"encoding/binary"
	"errors"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	onceRaw sync.Once
	fd4     = -1
	fd6     = -1
	markVal uint32
)

func ensureRawOnce(mark uint) {
	onceRaw.Do(func() {
		markVal = uint32(mark)
		openRaw()
	})
}

func openRaw() {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err == nil {
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(markVal))
		fd4 = fd
	}
	fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err == nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(markVal))
		fd6 = fd
	}
}

func sendRaw(pkt []byte) error {
	if len(pkt) < 1 {
		return nil
	}
	v := pkt[0] >> 4
	if v == 4 {
		if fd4 < 0 {
			return errors.New("raw4")
		}
		sa := &unix.SockaddrInet4{}
		copy(sa.Addr[:], pkt[16:20])
		return unix.Sendto(fd4, pkt, 0, sa)
	}
	if v == 6 {
		if fd6 < 0 {
			return errors.New("raw6")
		}
		sa := &unix.SockaddrInet6{ZoneId: 0}
		copy(sa.Addr[:], pkt[24:40])
		return unix.Sendto(fd6, pkt, 0, sa)
	}
	return nil
}

func tcpChecksumIPv4(ip, tcp []byte, data []byte) uint16 {
	sum := uint32(0)
	for i := 12; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	sum += uint32(6)
	sum += uint32(len(tcp) + len(data))
	tcpSum := checksum(tcp[:16], 0) + checksum(tcp[18:], 0)
	sum += tcpSum
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(uint16(data[len(data)-1]) << 8)
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func udpChecksumIPv4(ip, udp []byte, data []byte) uint16 {
	sum := uint32(0)
	for i := 12; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	sum += uint32(17)
	sum += uint32(len(udp) + len(data))
	udpSum := checksum(udp[:6], 0) + checksum(udp[8:], 0)
	sum += udpSum
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(uint16(data[len(data)-1]) << 8)
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func udpChecksumIPv6(ip6, udp []byte, data []byte) uint16 {
	sum := uint32(0)
	for i := 8; i < 40; i += 2 {
		if i == 24 {
			i = 40
			break
		}
		sum += uint32(binary.BigEndian.Uint16(ip6[i : i+2]))
	}
	for i := 24; i < 40; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip6[i : i+2]))
	}
	sum += uint32(len(udp) + len(data))
	sum += uint32(17)
	udpSum := checksum(udp[:6], 0) + checksum(udp[8:], 0)
	sum += udpSum
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(uint16(data[len(data)-1]) << 8)
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func checksum(b []byte, s uint32) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		s += uint32(uint16(b[len(b)-1]) << 8)
	}
	for s > 0xffff {
		s = (s >> 16) + (s & 0xffff)
	}
	return s
}

func putIPChecksum(ip []byte) {
	s := uint32(0)
	for i := 0; i < len(ip); i += 2 {
		if i == 10 {
			continue
		}
		s += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	for s > 0xffff {
		s = (s >> 16) + (s & 0xffff)
	}
	binary.BigEndian.PutUint16(ip[10:12], ^uint16(s))
}

func CloseRaw() error {
	var err error
	if fd4 >= 0 {
		err = unix.Close(fd4)
		fd4 = -1
	}
	if fd6 >= 0 {
		_ = unix.Close(fd6)
		fd6 = -1
	}
	return err
}

func init() {
	_ = syscall.Getpid()
}
