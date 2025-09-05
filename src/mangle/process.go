package mangle

import (
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/sni"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Verdict int

const (
	VerdictAccept Verdict = iota
	VerdictDrop
	VerdictContinue
)

func IPVersion(pkt []byte) int {
	if len(pkt) < 1 {
		return 0
	}
	switch pkt[0] >> 4 {
	case 4:
		return 4
	case 6:
		return 6
	default:
		return 0
	}
}

func ProcessPacket(cfg *config.Config, bytes []byte) Verdict {
	var (
		ip4 layers.IPv4
		ip6 layers.IPv6
		tcp layers.TCP
		udp layers.UDP
		pl  gopacket.Payload
	)

	first := layers.LayerTypeIPv4
	if IPVersion(bytes) == 6 {
		first = layers.LayerTypeIPv6
	}

	parser := gopacket.NewDecodingLayerParser(first, &ip4, &ip6, &tcp, &udp, &pl)
	decoded := []gopacket.LayerType{}
	if err := parser.DecodeLayers(bytes, &decoded); err != nil {
		return VerdictAccept
	}

	var ip4p *layers.IPv4
	var ip6p *layers.IPv6
	for _, lt := range decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			ip4p = &ip4
		case layers.LayerTypeIPv6:
			ip6p = &ip6
		}
	}

	for _, lt := range decoded {
		switch lt {
		case layers.LayerTypeTCP:
			if tcp.DstPort != 443 && tcp.SrcPort != 443 {
				continue
			}
			v := processTCP(&tcp, ip4p, ip6p, bytes)
			if v != VerdictContinue {
				return v
			}
		case layers.LayerTypeUDP:
			if udp.DstPort != 443 && udp.SrcPort != 443 {
				continue
			}
			if len(udp.Payload) == 0 {
				continue
			}
			if host, ok := sni.ParseQUICClientHelloSNI(udp.Payload); ok && host != "" {
				//	log.Infof("Target SNI detected (QUIC): %s", host)
			}
		}
	}

	return VerdictAccept
}
