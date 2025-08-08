// processor/ct.go
package processor

import (
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
