// queue/queue.go
package queue

import (
	"context"

	nfqueue "github.com/florianl/go-nfqueue"

	"github.com/daniellavrushin/b4/logx"
	"github.com/daniellavrushin/b4/processor"
)

type nfqIface interface {
	RegisterWithErrorFunc(ctx context.Context,
		fn nfqueue.HookFunc, errFn nfqueue.ErrorFunc) error
	SetVerdict(id uint32, verdict int) error
	Close() error
}

var openNFQ = func(c *nfqueue.Config) (nfqIface, error) {
	return nfqueue.Open(c)
}

type Worker struct {
	q      nfqIface
	id     uint16
	ctx    context.Context
	cancel context.CancelFunc
}

type Config struct {
	ID            uint16 // NFQUEUE number
	WithGSO       bool
	WithConntrack bool
	FailOpen      bool
}

func NewWorker(conf Config, cb processor.Callback) (*Worker, error) {
	flags := uint32(0)
	if conf.FailOpen {
		flags |= nfqueue.NfQaCfgFlagFailOpen
	}
	if conf.WithGSO {
		flags |= nfqueue.NfQaCfgFlagGSO
	}
	if conf.WithConntrack {
		flags |= nfqueue.NfQaCfgFlagConntrack
	}

	q, err := openNFQ(&nfqueue.Config{
		NfQueue:      conf.ID,
		MaxPacketLen: 0xffff, // copy full packet
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        flags,
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	// ------------------------------------------------------------------
	// The callback signature **must** match nfqueue.HookFunc.
	// ------------------------------------------------------------------
	hook := func(a nfqueue.Attribute) int {
		// Re‑use the existing processor interface — it expects *Attribute.
		verdict := cb(&a)

		// a.PacketID is *uint32 ; guard against nil just in case.
		if a.PacketID != nil {
			_ = q.SetVerdict(*a.PacketID, verdict)
		}
		return 0 // continue receiving packets
	}

	errHook := func(err error) int {
		logx.Errorf("nfqueue(%d): %v", conf.ID, err)
		return 0
	}

	if err := q.RegisterWithErrorFunc(ctx, hook, errHook); err != nil {
		cancel()
		_ = q.Close()
		return nil, err
	}

	return &Worker{q: q, id: conf.ID, ctx: ctx, cancel: cancel}, nil
}

// Run blocks until Close() is called.
func (w *Worker) Run() error {
	<-w.ctx.Done()
	return nil
}

func (w *Worker) Close() {
	if w == nil {
		return
	}
	if w.cancel != nil {
		w.cancel()
	}
	if w.q != nil {
		_ = w.q.Close()
	}
}
