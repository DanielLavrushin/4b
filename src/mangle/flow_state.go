package mangle

import (
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

type doneFlag struct{ t time.Time }

var flowsDone sync.Map // key -> doneFlag

func flowKey4(ip4 *layers.IPv4, ip6 *layers.IPv6, tcp *layers.TCP) string {
	if ip4 != nil {
		return ip4.SrcIP.String() + ":" + tcp.SrcPort.String() + ">" +
			ip4.DstIP.String() + ":" + tcp.DstPort.String()
	}
	if ip6 != nil {
		return ip6.SrcIP.String() + ":" + tcp.SrcPort.String() + ">" +
			ip6.DstIP.String() + ":" + tcp.DstPort.String()
	}
	return "?"
}

func flowIsDone(ip4 *layers.IPv4, ip6 *layers.IPv6, tcp *layers.TCP) bool {
	key := flowKey4(ip4, ip6, tcp)
	v, ok := flowsDone.Load(key)
	if !ok {
		return false
	}
	if time.Since(v.(doneFlag).t) > 5*time.Minute {
		flowsDone.Delete(key)
		return false
	}
	return true
}

func flowMarkDone(ip4 *layers.IPv4, ip6 *layers.IPv6, tcp *layers.TCP) {
	key := flowKey4(ip4, ip6, tcp)
	flowsDone.Store(key, doneFlag{t: time.Now()})
}
