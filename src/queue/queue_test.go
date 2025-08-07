package queue

import (
	"context"
	"testing"

	nfqueue "github.com/florianl/go-nfqueue"
)

/* ---------------------------------------------------------------------
   1)  stub implementation that satisfies nfqIface
--------------------------------------------------------------------- */

type stubQueue struct {
	hook      nfqueue.HookFunc
	verdictID uint32
	verdictCd int
	closeCnt  int
}

func (s *stubQueue) RegisterWithErrorFunc(_ context.Context,
	fn nfqueue.HookFunc, _ nfqueue.ErrorFunc) error {
	s.hook = fn
	return nil
}
func (s *stubQueue) SetVerdict(id uint32, cd int) error {
	s.verdictID, s.verdictCd = id, cd
	return nil
}
func (s *stubQueue) Close() error { s.closeCnt++; return nil }

/* ---------------------------------------------------------------------
   2)  the actual test
--------------------------------------------------------------------- */

func TestNewWorker_RegistersHookAndVerdict(t *testing.T) {
	// swap the opener
	orig := openNFQ
	var stub *stubQueue
	openNFQ = func(_ *nfqueue.Config) (nfqIface, error) {
		stub = &stubQueue{}
		return stub, nil
	}
	defer func() { openNFQ = orig }()

	// fake processor callback -> always returns DROP
	cb := func(*nfqueue.Attribute) int { return nfqueue.NfDrop }

	// create worker (should call our stub opener)
	w, err := NewWorker(Config{ID: 99}, cb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w == nil || stub == nil {
		t.Fatalf("stub not initialised")
	}

	// simulate a packet arriving at the registered hook
	pktID := uint32(4242)
	attr := nfqueue.Attribute{PacketID: &pktID}
	stub.hook(attr) // invoke

	// verify SetVerdict was called with the values we expect
	if stub.verdictID != pktID || stub.verdictCd != nfqueue.NfDrop {
		t.Fatalf("SetVerdict called with id=%d, verdict=%d (want id=%d, verdict=%d)",
			stub.verdictID, stub.verdictCd, pktID, nfqueue.NfDrop)
	}

	// worker.Close() must forward to queue.Close() and cancel ctx
	done := make(chan struct{})
	go func() { _ = w.Run(); close(done) }() // Run blocks on ctx

	w.Close() // triggers ctx cancellation
	<-done    // Run returns
	if stub.closeCnt == 0 {
		t.Fatalf("queue.Close not called")
	}
}
