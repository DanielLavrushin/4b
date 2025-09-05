package mangle

import (
	"strings"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Verdict int

const (
	VerdictAccept Verdict = iota
	VerdictDrop
	VerdictContinue
)

var (
	defaultFragStrategyTCP   = true
	defaultFragSNIReverse    = true
	defaultFragMiddleSNI     = true
	defaultFragSNIPos        = 1
	defaultFakeSeqOffset     = 10000
	defaultFakeSNISeqLen     = 1
	defaultSeg2Delay         = 0 * time.Millisecond
	defaultUDPModeFake       = true
	defaultUDPFakeSeqLen     = 6
	defaultUDPFakeLen        = 64
	defaultUDPFakingChecksum = false
)

func Process(cfg *config.Config, pkt []byte) Verdict {
	if cfg == nil || len(pkt) < 1 {
		return VerdictAccept
	}
	ensureRawOnce(cfg.Mark)
	dec := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ipv4, &ipv6, &tcp, &udp, &payload)
	decoded := decodedLayers[:0]
	if err := dec.DecodeLayers(pkt, &decoded); err != nil {
		return VerdictAccept
	}
	matcher := func(host string) bool { return anySuffixMatch(strings.ToLower(host), cfg.SNIDomains) }
	for _, l := range decoded {
		switch l {
		case layers.LayerTypeTCP:
			if tcp.DstPort != 443 && tcp.SrcPort != 443 {
				continue
			}
			rawL3 := pkt
			if ipv4.LayerContents() != nil {
				rawL3 = pkt
			} else if ipv6.LayerContents() != nil {
				rawL3 = pkt
			}
			return processTCP(matcher, rawL3)
		case layers.LayerTypeUDP:
			if udp.DstPort != 443 && udp.SrcPort != 443 {
				continue
			}
			if len(udp.Payload) == 0 {
				continue
			}
			if ipv4.LayerContents() != nil {
				return processUDP(matcher, pkt, false)
			} else if ipv6.LayerContents() != nil {
				return processUDP(matcher, pkt, true)
			}
		}
	}
	return VerdictAccept
}

func anySuffixMatch(host string, suffixes []string) bool {
	if host == "" || len(suffixes) == 0 {
		return false
	}
	for _, s := range suffixes {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "*.") {
			s = strings.TrimPrefix(s, "*.")
		}
		if strings.HasPrefix(s, ".") {
			s = strings.TrimPrefix(s, ".")
		}
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

var (
	ipv4    layers.IPv4
	ipv6    layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	payload gopacket.Payload

	decodedLayers [8]gopacket.LayerType
)
