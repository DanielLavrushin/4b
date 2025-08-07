// mangle/packet.go
package mangle

import (
	"github.com/daniellavrushin/4b/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Verdict int

const (
	VerdictAccept Verdict = iota
	VerdictDrop
	VerdictContinue
)

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

	// figure out which IP header we actually have
	var ip4p *layers.IPv4
	var ip6p *layers.IPv6
	for _, lt := range decoded {
		if lt == layers.LayerTypeIPv4 {
			ip4p = &ip4
		}
		if lt == layers.LayerTypeIPv6 {
			ip6p = &ip6
		}
	}

	for _, sec := range cfg.Sections() {
		verdict := VerdictContinue
		for _, lt := range decoded {
			switch lt {
			case layers.LayerTypeTCP:
				verdict = processTCP(&tcp, ip4p, ip6p, pl, sec, bytes)
			case layers.LayerTypeUDP:
				verdict = processUDP(&udp, ip4p, ip6p, pl, sec, bytes)
			}
			if verdict != VerdictContinue {
				return verdict
			}
		}
	}
	return VerdictAccept
}
