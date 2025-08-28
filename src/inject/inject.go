package inject

import (
	"math/rand"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

type Injector struct {
	fd int
}

func New(mark int) (*Injector, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if mark != 0 {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark)
	}
	rand.Seed(time.Now().UnixNano())
	return &Injector{fd: fd}, nil
}

func (i *Injector) Close() { _ = unix.Close(i.fd) }

func (i *Injector) send(dst net.IP, b []byte) {
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], dst.To4())
	_ = syscall.Sendto(i.fd, b, 0, &sa)
}

func buildIPv4TCP(ip4 *layers.IPv4, tcp *layers.TCP, payload []byte, seq uint32) ([]byte, error) {
	ip := &layers.IPv4{
		Version: 4, TOS: ip4.TOS, Id: uint16(rand.Intn(65535)),
		Flags: ip4.Flags, FragOffset: 0, TTL: ip4.TTL, Protocol: layers.IPProtocolTCP,
		SrcIP: ip4.SrcIP, DstIP: ip4.DstIP,
	}
	t := &layers.TCP{
		SrcPort: tcp.SrcPort, DstPort: tcp.DstPort,
		Seq: seq, Ack: tcp.Ack,
		PSH: tcp.PSH, ACK: true, Window: tcp.Window,
	}
	t.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		ip, t, gopacket.Payload(payload),
	)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (i *Injector) SplitAndInject(pkt gopacket.Packet, splitAt int) {
	ip4l := pkt.Layer(layers.LayerTypeIPv4)
	tl := pkt.Layer(layers.LayerTypeTCP)
	if ip4l == nil || tl == nil {
		return
	}
	ip4 := ip4l.(*layers.IPv4)
	tcp := tl.(*layers.TCP)
	pl := tcp.Payload
	if len(pl) < 2 || splitAt <= 0 || splitAt >= len(pl) {
		return
	}
	head := pl[:splitAt]
	tail := pl[splitAt:]
	seq0 := tcp.Seq
	seqTail := seq0 + uint32(len(head))
	bTail, err1 := buildIPv4TCP(ip4, tcp, tail, seqTail)
	bHead, err2 := buildIPv4TCP(ip4, tcp, head, seq0)
	if err1 == nil && err2 == nil {
		i.send(ip4.DstIP, bTail)
		i.send(ip4.DstIP, bHead)
	}
}
