package mangle

import (
	"github.com/daniellavrushin/4b/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func processUDP(udp *layers.UDP, ip4 *layers.IPv4, ip6 *layers.IPv6, payload gopacket.Payload, sec *config.Section, origPacket []byte) Verdict {
	return VerdictContinue
}
