//go:build linux

package sni

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/log"
	"golang.org/x/sys/unix"
)

type FiveTuple struct {
	V6      bool
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
}

type Config struct {
	Iface               string
	SnapLen             int
	FlowTTL             time.Duration
	MaxClientHelloBytes int
	Promisc             bool
	Matcher             *SuffixSet
	OnTLSHost           func(FiveTuple, string)
	OnQUICHost          func(FiveTuple, string)
}

type Sniffer struct {
	fd         int
	ifindex    int
	buf        []byte
	cfg        Config
	mu         sync.Mutex
	flows      map[FiveTuple]*flow
	stop       chan struct{}
	wg         sync.WaitGroup
	promiscSet bool
}

type flow struct {
	baseSeq uint32
	nextSeq uint32
	buf     []byte
	last    time.Time
}

func NewSniffer(cfg Config) (*Sniffer, error) {
	if cfg.SnapLen <= 0 {
		cfg.SnapLen = 96 * 1024
	}
	if cfg.FlowTTL <= 0 {
		cfg.FlowTTL = 10 * time.Second
	}
	if cfg.MaxClientHelloBytes <= 0 {
		cfg.MaxClientHelloBytes = 8192
	}
	ifi, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	tv := unix.Timeval{Sec: 0, Usec: 200000}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, err
	}
	prom := false
	if cfg.Promisc {
		m := &unix.PacketMreq{Ifindex: int32(ifi.Index), Type: unix.PACKET_MR_PROMISC}
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, m); err == nil {
			prom = true
		} else {
			log.Errorf("PROMISC enable failed on %s: %v", cfg.Iface, err)
		}
	}
	s := &Sniffer{
		fd:         fd,
		ifindex:    ifi.Index,
		buf:        make([]byte, cfg.SnapLen),
		cfg:        cfg,
		flows:      make(map[FiveTuple]*flow, 1024),
		stop:       make(chan struct{}),
		promiscSet: prom,
	}
	return s, nil
}

func (s *Sniffer) Run() {
	s.wg.Add(2)
	go s.rxLoop()
	go s.gcLoop()
}

func (s *Sniffer) Close() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	if s.promiscSet {
		_ = unix.SetsockoptPacketMreq(s.fd, unix.SOL_PACKET, unix.PACKET_DROP_MEMBERSHIP, &unix.PacketMreq{Ifindex: int32(s.ifindex), Type: unix.PACKET_MR_PROMISC})
	}
	_ = unix.Close(s.fd)
	s.wg.Wait()
}

func (s *Sniffer) rxLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		n, from, err := unix.Recvfrom(s.fd, s.buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				continue
			}
			return
		}
		ll, _ := from.(*unix.SockaddrLinklayer)
		if ll != nil && ll.Ifindex == s.ifindex {
			s.handleFrame(s.buf[:n])
		}
	}
}

func (s *Sniffer) gcLoop() {
	defer s.wg.Done()
	t := time.NewTicker(s.cfg.FlowTTL / 2)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			now := time.Now()
			s.mu.Lock()
			for k, f := range s.flows {
				if now.Sub(f.last) > s.cfg.FlowTTL {
					delete(s.flows, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Sniffer) handleFrame(b []byte) {
	off, ok := parseEther(b)
	if !ok {
		return
	}
	if len(b) < off+1 {
		return
	}
	switch b[off] >> 4 {
	case 4:
		s.handleIPv4(b[off:])
	case 6:
		s.handleIPv6(b[off:])
	}
}

func (s *Sniffer) handleIPv4(ip []byte) {
	if len(ip) < 20 {
		return
	}
	ihl := int(ip[0]&0x0F) * 4
	if ihl < 20 || len(ip) < ihl {
		return
	}
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if total > len(ip) {
		total = len(ip)
	}
	if total < ihl {
		return
	}
	proto := ip[9]
	src := ip[12:16]
	dst := ip[16:20]
	pl := ip[ihl:total]
	switch proto {
	case 6:
		s.handleTCP(false, src, dst, pl)
	case 17:
		s.handleUDP(false, src, dst, pl)
	}
}

func (s *Sniffer) handleIPv6(ip6 []byte) {
	if len(ip6) < 40 {
		return
	}
	nxt := ip6[6]
	src := ip6[8:24]
	dst := ip6[24:40]
	payload := ip6[40:]
	for {
		if len(payload) < 1 {
			return
		}
		if nxt == 6 || nxt == 17 {
			break
		}
		if len(payload) < 2 {
			return
		}
		h := int(payload[1]+1) * 8
		if h > len(payload) {
			return
		}
		nxt = payload[0]
		payload = payload[h:]
	}
	switch nxt {
	case 6:
		s.handleTCP(true, src, dst, payload)
	case 17:
		s.handleUDP(true, src, dst, payload)
	}
}

func (s *Sniffer) handleUDP(v6 bool, src, dst, udp []byte) {
	if len(udp) < 8 {
		return
	}
	dport := binary.BigEndian.Uint16(udp[2:4])
	if dport != 443 {
		return
	}
	payload := udp[8:]
	if len(payload) == 0 {
		return
	}
	log.Tracef("UDP:443 seen v6=%v len=%d", v6, len(payload))
	var key FiveTuple
	fillKey(&key, v6, src, dst, binary.BigEndian.Uint16(udp[0:2]), dport)
	host, ok := ParseQUICClientHelloSNI(payload)
	log.Tracef("QUIC SNI parse: %v, host=%q", ok, host)
	if !ok || host == "" {
		return
	}
	if s.cfg.Matcher != nil && !s.cfg.Matcher.Match(host) {
		return
	}
	log.Infof("Target SNI detected (QUIC): %s", host)
	if s.cfg.OnQUICHost != nil {
		s.cfg.OnQUICHost(key, host)
	}
}

func (s *Sniffer) handleTCP(v6 bool, src, dst, tcp []byte) {
	if len(tcp) < 20 {
		return
	}
	dataOff := int((tcp[12] >> 4) * 4)
	if dataOff < 20 || len(tcp) < dataOff {
		return
	}
	flags := tcp[13]
	sport := binary.BigEndian.Uint16(tcp[0:2])
	dport := binary.BigEndian.Uint16(tcp[2:4])
	if dport != 443 {
		return
	}
	seq := binary.BigEndian.Uint32(tcp[4:8])
	payload := tcp[dataOff:]
	log.Tracef("TCP:443 seen v6=%v flags=0x%02x seq=%d len=%d", v6, flags, seq, len(payload))
	var key FiveTuple
	fillKey(&key, v6, src, dst, sport, dport)
	now := time.Now()
	s.mu.Lock()
	f, ok := s.flows[key]
	if !ok {
		f = &flow{buf: make([]byte, 0, 4096), last: now}
		s.flows[key] = f
	}
	if (flags & 0x02) != 0 {
		f.baseSeq = seq
		f.nextSeq = seq + 1
		f.buf = f.buf[:0]
	}
	if len(payload) > 0 {
		if f.nextSeq == 0 {
			f.baseSeq = seq
			f.nextSeq = seq
		}
		switch {
		case seq == f.nextSeq:
			f.buf = appendCap(f.buf, payload, s.cfg.MaxClientHelloBytes)
			f.nextSeq += uint32(len(payload))
		case seq < f.nextSeq:
			alr := int(f.nextSeq - seq)
			if alr < len(payload) {
				f.buf = appendCap(f.buf, payload[alr:], s.cfg.MaxClientHelloBytes)
				f.nextSeq += uint32(len(payload) - alr)
			}
		default:
		}
		f.last = now
		if len(f.buf) >= 5 {
			host, ok := ParseTLSClientHelloSNI(f.buf)
			log.Tracef("TLS SNI parse: %v, host=%q", ok, host)
			if ok && host != "" {
				if s.cfg.Matcher != nil && !s.cfg.Matcher.Match(host) {
					delete(s.flows, key)
					s.mu.Unlock()
					return
				}
				log.Infof("Target SNI detected (TLS): %s", host)
				delete(s.flows, key)
				s.mu.Unlock()
				if s.cfg.OnTLSHost != nil {
					s.cfg.OnTLSHost(key, host)
				}
				return
			}
		}
		if len(f.buf) >= s.cfg.MaxClientHelloBytes {
			log.Tracef("TLS: buffer cap %d reached without ClientHello", s.cfg.MaxClientHelloBytes)
			delete(s.flows, key)
		}
	} else {
		f.last = now
	}
	s.mu.Unlock()
}

func appendCap(dst, src []byte, capLimit int) []byte {
	if len(dst) >= capLimit {
		return dst[:capLimit]
	}
	space := capLimit - len(dst)
	if space <= 0 {
		return dst
	}
	if len(src) > space {
		src = src[:space]
	}
	return append(dst, src...)
}

func fillKey(k *FiveTuple, v6 bool, src, dst []byte, sport, dport uint16) {
	k.V6 = v6
	k.SrcPort = sport
	k.DstPort = dport
	if v6 {
		copy(k.SrcIP[:], src[:16])
		copy(k.DstIP[:], dst[:16])
	} else {
		copy(k.SrcIP[12:], src[:4])
		copy(k.DstIP[12:], dst[:4])
	}
}

func parseEther(b []byte) (int, bool) {
	if len(b) < 14 {
		return 0, false
	}
	off := 12
	ethType := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	for ethType == 0x8100 || ethType == 0x88a8 {
		if len(b) < off+4 {
			return 0, false
		}
		ethType = int(binary.BigEndian.Uint16(b[off+2:]))
		off += 4
	}
	switch ethType {
	case 0x0800, 0x86DD:
		return off, true
	default:
		return 0, false
	}
}

func htons(x uint16) uint16 { return (x<<8)&0xff00 | x>>8 }
