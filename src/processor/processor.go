package processor

import (
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/mangle"
	nfqueue "github.com/florianl/go-nfqueue"
)

type Callback func(*nfqueue.Attribute) int

var processPacket = mangle.ProcessPacket

func New(cfg *config.Config) Callback {
	return func(a *nfqueue.Attribute) int {
		// Skip packets that already carry our mark (avoid loops)
		if a.Mark != nil && ((*a.Mark)&uint32(cfg.Mark)) == uint32(cfg.Mark) {
			return nfqueue.NfAccept
		}
		if a.Payload == nil || len(*a.Payload) == 0 {
			return nfqueue.NfAccept
		}
		switch processPacket(cfg, *a.Payload) {
		case mangle.VerdictDrop:
			return nfqueue.NfDrop
		default:
			return nfqueue.NfAccept
		}
	}
}
