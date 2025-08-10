// queue/queue.go
package queue

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix" // <-- add

	"github.com/daniellavrushin/b4/logx"
	"github.com/daniellavrushin/b4/processor"
)

type nfqIface interface {
	RegisterWithErrorFunc(ctx context.Context, fn nfqueue.HookFunc, errFn nfqueue.ErrorFunc) error
	SetVerdict(id uint32, verdict int) error
	Close() error
}

var openNFQ = func(c *nfqueue.Config) (nfqIface, error) {
	nf, err := nfqueue.Open(c)
	if err != nil {
		return nil, err
	}
	_ = nf.SetOption(netlink.NoENOBUFS, true)
	return nf, nil
}

type Worker struct {
	qs     []nfqIface // <-- handle both AFs
	id     uint16
	ctx    context.Context
	cancel context.CancelFunc
}

type Config struct {
	ID            uint16
	WithGSO       bool
	WithConntrack bool
	FailOpen      bool
}

func ipv6Available() bool {
	fi, err := os.Stat("/proc/net/if_inet6")
	if err != nil {
		return false
	}
	return fi.Size() > 0
}

func NewWorker(conf Config, cb processor.Callback) (*Worker, error) {
	flags := uint32(0)

	logx.Tracef("nfqueue(%d): NfQaCfgFlagFailOpen=%v, NfQaCfgFlagGSO=%v, NfQaCfgFlagConntrack=%v",
		conf.ID, conf.FailOpen, conf.WithGSO, conf.WithConntrack)

	if conf.FailOpen {
		flags |= nfqueue.NfQaCfgFlagFailOpen
	}
	if conf.WithGSO {
		flags |= nfqueue.NfQaCfgFlagGSO
	}
	if conf.WithConntrack {
		flags |= nfqueue.NfQaCfgFlagConntrack
	}
	logx.Tracef("nfqueue(%d): flags=0x%x", conf.ID, flags)

	ctx, cancel := context.WithCancel(context.Background())

	errHook := func(err error) int {
		if ctx.Err() != nil ||
			errors.Is(err, os.ErrClosed) ||
			strings.Contains(err.Error(), "closed") {
			return 0
		}
		logx.Errorf("nfqueue(%d): %v", conf.ID, err)
		return 0
	}

	var qs []nfqIface
	fams := []uint8{unix.AF_INET}
	if ipv6Available() {
		fams = append(fams, unix.AF_INET6)
	}
	for _, af := range fams {
		q, err := openNFQ(&nfqueue.Config{
			AfFamily:     af,
			NfQueue:      conf.ID,
			MaxPacketLen: 0xFFFF,
			MaxQueueLen:  0x800, // 2048
			Copymode:     nfqueue.NfQnlCopyPacket,
			Flags:        flags,
		})
		if err != nil {
			// allow IPv6 to be absent on some routers
			if af == unix.AF_INET6 {
				es := strings.ToLower(err.Error())
				if strings.Contains(es, "address family not supported") ||
					strings.Contains(es, "eafnosupport") ||
					strings.Contains(es, "operation not permitted") ||
					strings.Contains(es, "permission denied") {
					logx.Infof("nfqueue(%d): IPv6 queue not available: %v (continuing with IPv4)", conf.ID, err)
					continue
				}
			}
			cancel()
			for _, z := range qs {
				_ = z.Close()
			}
			return nil, fmt.Errorf("nfqueue(%d, af=%d): %w", conf.ID, af, err)
		}
		// hook must capture this specific q
		hook := func(a nfqueue.Attribute) int {
			v := cb(&a) // already nfqueue verdict (int)
			if a.PacketID != nil {
				if err := q.SetVerdict(*a.PacketID, v); err != nil {
					logx.Errorf("nfqueue(%d) SetVerdict id=%d: %v", conf.ID, *a.PacketID, err)
				}
			}
			return 0
		}

		if err := q.RegisterWithErrorFunc(ctx, hook, errHook); err != nil {
			if af == unix.AF_INET6 {
				es := strings.ToLower(err.Error())
				if strings.Contains(es, "operation not permitted") ||
					strings.Contains(es, "permission denied") ||
					strings.Contains(es, "address family not supported") ||
					strings.Contains(es, "protocol not supported") ||
					strings.Contains(es, "eafnosupport") {
					logx.Infof("nfqueue(%d): IPv6 register skipped: %v (continuing with IPv4)", conf.ID, err)
					_ = q.Close()
					continue
				}
			}
			cancel()
			_ = q.Close()
			for _, z := range qs {
				_ = z.Close()
			}
			return nil, err
		}
		logx.Tracef("nfqueue(%d): bound af=%d", conf.ID, af)
		qs = append(qs, q)
	}
	if len(qs) == 0 {
		cancel()
		return nil, fmt.Errorf("nfqueue(%d): failed to bind AF_INET/AF_INET6", conf.ID)
	}
	return &Worker{qs: qs, id: conf.ID, ctx: ctx, cancel: cancel}, nil
}

func (w *Worker) Run() error { <-w.ctx.Done(); return nil }

func (w *Worker) Close() {
	if w == nil {
		return
	}
	if w.cancel != nil {
		w.cancel()
	}
	for _, q := range w.qs {
		_ = q.Close()
	}
}
