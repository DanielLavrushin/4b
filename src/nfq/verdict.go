package nfq

import (
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/mangle"
	"github.com/florianl/go-nfqueue"
)

const packetMark uint32 = 32768 // 0x8000

func Callback(q *nfqueue.Nfqueue, sec *config.Section) func(*nfqueue.Attribute) int {
	return func(a *nfqueue.Attribute) int {
		var raw []byte
		if a.Payload != nil {
			raw = *a.Payload
		}
		var id uint32
		if a.PacketID != nil {
			id = *a.PacketID
		} else {
			_ = q.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		v := handlePacket(sec, raw)

		switch v {
		case mangle.VerdictDrop:
			_ = q.SetVerdict(id, nfqueue.NfDrop)
			return 0

		case mangle.VerdictAccept, mangle.VerdictContinue:
			_ = q.SetVerdictWithMark(id, nfqueue.NfAccept, int(packetMark))
			return 0
		}

		_ = q.SetVerdictWithMark(id, nfqueue.NfAccept, int(packetMark))
		return 0
	}
}
