package sni

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

type SniInfo struct {
	SNI   string
	SrcIP string
	DstIP string
	Proto string
}

type Sniffer struct {
	ifaces []string
	tps    []*afpacket.TPacket
}

func ParseSNI(payload []byte) (string, bool) {
	// Parse the SNI from the TLS Client Hello payload
	return "", false
}

func (s *Sniffer) Run(ctx context.Context) (<-chan SniInfo, <-chan error) {
	out := make(chan SniInfo, 256)
	errc := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(len(s.tps))
	for _, tp := range s.tps {
		src := gopacket.NewPacketSource(tp, layers.LinkTypeEthernet)
		packets := src.Packets()
		go func(pkts <-chan gopacket.Packet) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case pkt, ok := <-pkts:
					if !ok {
						return
					}
					netl := pkt.NetworkLayer()
					if netl == nil {
						continue
					}
					var srcIP, dstIP string
					switch nl := netl.(type) {
					case *layers.IPv4:
						srcIP = nl.SrcIP.String()
						dstIP = nl.DstIP.String()
					case *layers.IPv6:
						srcIP = nl.SrcIP.String()
						dstIP = nl.DstIP.String()
					default:
						continue
					}
					if tl := pkt.Layer(layers.LayerTypeTCP); tl != nil {
						tcp := tl.(*layers.TCP)
						if tcp.DstPort != 443 && tcp.SrcPort != 443 {
							continue
						}
						if len(tcp.Payload) == 0 {
							continue
						}
						if name, ok := ParseTLSClientHelloSNI(tcp.Payload); ok {
							out <- SniInfo{SNI: name, SrcIP: srcIP, DstIP: dstIP, Proto: "TCP"}
						}
						continue
					}
					if ul := pkt.Layer(layers.LayerTypeUDP); ul != nil {
						udp := ul.(*layers.UDP)
						if udp.DstPort != 443 && udp.SrcPort != 443 {
							continue
						}
						if udp.DstPort != 443 {
							continue
						}
						if name, ok := ParseQUICClientHelloSNI(udp.Payload); ok {
							out <- SniInfo{SNI: name, SrcIP: srcIP, DstIP: dstIP, Proto: "QUIC"}
						}
						continue
					}
				}
			}
		}(packets)
	}
	go func() {
		wg.Wait()
		for _, tp := range s.tps {
			tp.Close()
		}
		close(out)
		close(errc)
	}()
	return out, errc
}

func (s *Sniffer) Close() error {
	if len(s.tps) == 0 {
		return errors.New("not open")
	}
	for _, tp := range s.tps {
		tp.Close()
	}
	return nil
}

func hostMatch(list []string) func(string) bool {
	if len(list) == 0 {
		return func(string) bool { return true }
	}
	return func(h string) bool {
		h = strings.ToLower(h)
		for _, d := range list {
			if h == d || strings.HasSuffix(h, "."+d) {
				return true
			}
		}
		return false
	}
}
