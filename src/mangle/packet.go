// mangle/packet.go
package mangle

import (
	"github.com/daniellavrushin/4b/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Verdict mirrors PKT_* in C
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

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeIPv4,
		&ip4, &ip6, &tcp, &udp, &pl,
	)
	decoded := []gopacket.LayerType{}
	if err := parser.DecodeLayers(bytes, &decoded); err != nil {
		return VerdictAccept // malformed → let kernel decide (original “goto accept”)
	}

	for _, sec := range cfg.Sections() {

		verdict := VerdictContinue

		for _, lt := range decoded {
			switch lt {
			case layers.LayerTypeTCP:
				verdict = processTCP(&tcp, &ip4, &ip6, pl, sec, bytes)
			case layers.LayerTypeUDP:
				verdict = processUDP(&udp, &ip4, &ip6, pl, sec, bytes)
			}
			if verdict != VerdictContinue {
				return verdict
			}
		}
	}
	// none of the sections cared ⇒ accept
	return VerdictAccept
}
