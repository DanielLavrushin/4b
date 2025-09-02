package nfq

import (
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/mangle"
	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
)

const (
	ctaCountersOrig  = 9
	ctaCountersReply = 10
)

const (
	ctaCountersUnspec    = 0
	ctaCountersPackets   = 1
	ctaCountersBytes     = 2
	ctaCounters32Packets = 3
	ctaCounters32Bytes   = 4
)

type Callback func(*nfqueue.Attribute) int

func MakeCallback(cfg *config.Config) Callback {
	return func(a *nfqueue.Attribute) int {
		if a == nil || a.Payload == nil {
			return int(nfqueue.NfAccept)
		}
		if a.Mark != nil && ((*a.Mark)&uint32(cfg.Mark)) == uint32(cfg.Mark) {
			return int(nfqueue.NfAccept)
		}
		if cfg.ConnBytesLimit > 0 && a.Ct != nil {
			if pkts, ok, _ := ctOrigPackets(*a.Ct); ok && pkts > uint64(cfg.ConnBytesLimit) {
				return int(nfqueue.NfAccept)
			}
		}
		switch mangle.ProcessPacket(cfg, *a.Payload) {
		case mangle.VerdictDrop:
			return int(nfqueue.NfDrop)
		default:
			return int(nfqueue.NfAccept)
		}
	}
}

func ctOrigPackets(ct []byte) (uint64, bool, error) {
	ad, err := netlink.NewAttributeDecoder(ct)
	if err != nil {
		return 0, false, err
	}
	var pkts uint64
	var have bool
	for ad.Next() {
		switch ad.Type() {
		case ctaCountersOrig:
			ad.Nested(func(cad *netlink.AttributeDecoder) error {
				for cad.Next() {
					switch cad.Type() {
					case ctaCountersPackets:
						pkts = cad.Uint64()
						have = true
					case ctaCounters32Packets:
						pkts = uint64(cad.Uint32())
						have = true
					}
				}
				return cad.Err()
			})
		}
	}
	if err := ad.Err(); err != nil {
		return 0, false, err
	}
	return pkts, have, nil
}
