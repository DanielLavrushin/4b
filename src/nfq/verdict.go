package nfq

import (
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/mangle"
	"github.com/daniellavrushin/b4/processor"
	"github.com/florianl/go-nfqueue"
)

const packetMark uint32 = 32768 // 0x8000

func MakeCallback(sec *config.Section) processor.Callback {
	return func(a *nfqueue.Attribute) int {
		if a == nil || a.Payload == nil {
			return int(nfqueue.NfAccept)
		}
		raw := *a.Payload

		v := HandlePacket(sec, raw)
		switch v {
		case mangle.VerdictDrop:
			return int(nfqueue.NfDrop)
		default:
			return int(nfqueue.NfAccept)
		}
	}
}
