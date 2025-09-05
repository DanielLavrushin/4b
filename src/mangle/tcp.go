package mangle

import (
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/sni"
	"github.com/google/gopacket/layers"
)

func processTCP(tcp *layers.TCP, ip4 *layers.IPv4, ip6 *layers.IPv6, raw []byte) Verdict {
	//log.Tracef("tcp syn=%v ack=%v psh=%v rst=%v fin=%v len=%d", tcp.SYN, tcp.ACK, tcp.PSH, tcp.RST, tcp.FIN, len(tcp.Payload))
	pl, ok := splitTCP(raw)

	if !ok || len(pl) == 0 {
		return VerdictContinue
	}
	prefix, base, ok := tcpAssemblePrefix(tcp, ip4, ip6, pl)
	log.Tracef("Assembled TCP prefix: %v", prefix)
	if !ok || len(prefix) == 0 {
		return VerdictContinue
	}
	off, have := findTLSClientHelloStart(prefix)
	log.Tracef("Found TLS ClientHello at offset: %d", off)
	if !have {
		return VerdictContinue
	}
	host, ok2 := sni.ParseTLSClientHelloSNI(prefix[off:])
	if !ok2 || host == "" {
		return VerdictContinue
	}
	_ = base
	log.Infof("Target SNI detected (TLS): %s", host)
	tcpStreamDelete(tcp, ip4, ip6)
	return VerdictAccept
}

func findTLSClientHelloStart(b []byte) (int, bool) {
	for i := 0; i+6 < len(b); i++ {
		if b[i] != 0x16 {
			continue
		}
		if b[i+1] != 0x03 {
			continue
		}
		if b[i+5] == 0x01 {
			return i, true
		}
	}
	return 0, false
}
