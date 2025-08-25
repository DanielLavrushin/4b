package nfq

import (
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/logx"
	"github.com/daniellavrushin/b4/mangle"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// handlePacket — 1-в-1 диспетчер: L3→L4, затем вызываем TCP/UDP-обработчики.
func handlePacket(sec *config.Section, raw []byte) mangle.Verdict {
	if len(raw) < 1 {
		return mangle.VerdictAccept
	}
	ver := raw[0] >> 4

	if ver == 4 {
		p := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.NoCopy)
		if el := p.ErrorLayer(); el != nil {
			logx.Tracef("decode v4 err: %v", el.Error())
			return mangle.VerdictAccept
		}
		ip4L := p.Layer(layers.LayerTypeIPv4)
		if ip4L == nil {
			return mangle.VerdictAccept
		}
		ip4 := ip4L.(*layers.IPv4)

		switch ip4.Protocol {
		case layers.IPProtocolTCP:
			tl := p.Layer(layers.LayerTypeTCP)
			if tl == nil {
				return mangle.VerdictAccept
			}
			tcp := tl.(*layers.TCP)
			// ApplicationLayer часто пуст (offload) — payload вычислим из raw внутри processTCP.
			return mangle.ProcessTCP(tcp, ip4, nil, nil, sec, raw)

		case layers.IPProtocolUDP:
			ul := p.Layer(layers.LayerTypeUDP)
			if ul == nil {
				return mangle.VerdictAccept
			}
			udp := ul.(*layers.UDP)
			var app gopacket.Payload
			if al := p.ApplicationLayer(); al != nil {
				app = gopacket.Payload(al.Payload())
			}
			return mangle.ProcessUDP(udp, ip4, nil, app, sec, raw)
		}

		return mangle.VerdictAccept
	}

	if ver == 6 {
		p := gopacket.NewPacket(raw, layers.LayerTypeIPv6, gopacket.NoCopy)
		if el := p.ErrorLayer(); el != nil {
			logx.Tracef("decode v6 err: %v", el.Error())
			return mangle.VerdictAccept
		}
		ip6L := p.Layer(layers.LayerTypeIPv6)
		if ip6L == nil {
			return mangle.VerdictAccept
		}
		ip6 := ip6L.(*layers.IPv6)

		switch ip6.NextHeader {
		case layers.IPProtocolTCP:
			tl := p.Layer(layers.LayerTypeTCP)
			if tl == nil {
				return mangle.VerdictAccept
			}
			tcp := tl.(*layers.TCP)
			return mangle.ProcessTCP(tcp, nil, ip6, nil, sec, raw)

		case layers.IPProtocolUDP:
			ul := p.Layer(layers.LayerTypeUDP)
			if ul == nil {
				return mangle.VerdictAccept
			}
			udp := ul.(*layers.UDP)
			var app gopacket.Payload
			if al := p.ApplicationLayer(); al != nil {
				app = gopacket.Payload(al.Payload())
			}
			return mangle.ProcessUDP(udp, nil, ip6, app, sec, raw)
		}

		return mangle.VerdictAccept
	}

	return mangle.VerdictAccept
}
