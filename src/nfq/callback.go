package nfq

import (
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/mangle"
	"github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
)

// ctattr_type (linux/netfilter/nfnetlink_conntrack.h)
const (
	ctaCountersOrig  = 9  // CTA_COUNTERS_ORIG
	ctaCountersReply = 10 // CTA_COUNTERS_REPLY
)

// ctattr_counters (linux/netfilter/nfnetlink_conntrack.h)
const (
	ctaCountersUnspec    = 0
	ctaCountersPackets   = 1 // CTA_COUNTERS_PACKETS (u64)
	ctaCountersBytes     = 2 // CTA_COUNTERS_BYTES (u64)
	ctaCounters32Packets = 3 // CTA_COUNTERS32_PACKETS (u32)
	ctaCounters32Bytes   = 4 // CTA_COUNTERS32_BYTES (u32)
)

const packetMark uint32 = 0xB4 // 0xB4

type Callback func(*nfqueue.Attribute) int

func New(cfg *config.Config) Callback {
	return func(a *nfqueue.Attribute) int {
		// 0) skip our own packets
		if a.Mark != nil && ((*a.Mark)&uint32(cfg.Mark)) == uint32(cfg.Mark) {
			return nfqueue.NfAccept
		}
		if a.Payload == nil || len(*a.Payload) == 0 {
			return nfqueue.NfAccept
		}

		// 1) conntrack threshold
		if cfg.ConnBytesLimit > 0 && a.Ct != nil {
			if pkts, ok, _ := ctOrigPackets(*a.Ct); ok && pkts > uint64(cfg.ConnBytesLimit) {
				return nfqueue.NfAccept
			}
		}

		// 2) normal processing
		switch mangle.ProcessPacket(cfg, *a.Payload) {
		case mangle.VerdictDrop:
			return nfqueue.NfDrop
		default:
			return nfqueue.NfAccept
		}
	}
}

func MakeCallback(sec *config.Config) Callback {
	return func(a *nfqueue.Attribute) int {
		if a == nil || a.Payload == nil {
			return int(nfqueue.NfAccept)
		}
		raw := *a.Payload

		v := mangle.ProcessPacket(sec, raw)
		switch v {
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
			// Decode the nested CTA_COUNTERS_* attributes
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
