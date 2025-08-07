package processor

import (
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/mangle"
	nfqueue "github.com/florianl/go-nfqueue"
)

/*
   Test matrix

   ┌────────────┬──────────┬─────────┐
   │ case       │ mark?    │ payload │ expected verdict │
   ├────────────┼──────────┼─────────┼──────────────────┤
   │ LoopSkip   │ yes      │ any     │ ACCEPT           │
   │ EmptyPay   │ no       │ empty   │ ACCEPT           │
   │ mangleDrop │ no       │ non‑nil │ DROP (stub)      │
   │ manglePass │ no       │ non‑nil │ ACCEPT (stub)    │
   └────────────┴──────────┴─────────┴──────────────────┘
*/

func TestCallback_VerdictMatrix(t *testing.T) {
	// shared fixtures
	cfg := config.DefaultConfig
	payload := []byte{0x01, 0x02}

	// helpers
	makeAttr := func(markSet bool, pay []byte) *nfqueue.Attribute {
		var attr nfqueue.Attribute
		if markSet {
			mark := uint32(cfg.Mark)
			attr.Mark = &mark
		}
		if pay != nil {
			attr.Payload = &pay
		}
		return &attr
	}

	//------------------------------------------------------------------
	// 1) Loop‑protection: mark already present → ACCEPT
	//------------------------------------------------------------------
	cb := New(&cfg)
	if v := cb(makeAttr(true, payload)); v != nfqueue.NfAccept {
		t.Fatalf("LoopSkip: verdict=%d want NfAccept", v)
	}

	//------------------------------------------------------------------
	// 2) Empty payload → ACCEPT
	//------------------------------------------------------------------
	if v := cb(makeAttr(false, nil)); v != nfqueue.NfAccept {
		t.Fatalf("EmptyPay: verdict=%d want NfAccept", v)
	}

	//------------------------------------------------------------------
	// 3 & 4) Force processPacket to return DROP then ACCEPT
	//------------------------------------------------------------------
	original := processPacket
	defer func() { processPacket = original }() // restore after test

	tests := []struct {
		name     string
		stubVerd mangle.Verdict
		want     int
	}{
		{"mangleDrop", mangle.VerdictDrop, nfqueue.NfDrop},
		{"manglePass", mangle.VerdictAccept, nfqueue.NfAccept},
	}

	for _, tc := range tests {
		processPacket = func(*config.Config, []byte) mangle.Verdict {
			return tc.stubVerd
		}
		cb := New(&cfg)
		if got := cb(makeAttr(false, payload)); got != tc.want {
			t.Fatalf("%s: verdict=%d want %d", tc.name, got, tc.want)
		}
	}
}
