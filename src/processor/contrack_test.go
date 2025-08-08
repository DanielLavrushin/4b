package processor

import (
	"testing"

	"github.com/mdlayher/netlink"
)

func encCtOrigPackets64(pkts uint64) []byte {
	ae := netlink.NewAttributeEncoder()
	ae.Nested(ctaCountersOrig, func(nae *netlink.AttributeEncoder) error {
		nae.Uint64(ctaCountersPackets, pkts)
		return nil
	})
	b, err := ae.Encode()
	if err != nil {
		panic(err)
	}
	return b
}

func encCtOrigPackets32(pkts uint32) []byte {
	ae := netlink.NewAttributeEncoder()
	ae.Nested(ctaCountersOrig, func(nae *netlink.AttributeEncoder) error {
		nae.Uint32(ctaCounters32Packets, pkts)
		return nil
	})
	b, err := ae.Encode()
	if err != nil {
		panic(err)
	}
	return b
}

func TestCtOrigPackets64(t *testing.T) {
	ct := encCtOrigPackets64(12345)
	got, ok, err := ctOrigPackets(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("want ok=true")
	}
	if got != 12345 {
		t.Fatalf("got %d want 12345", got)
	}
}

func TestCtOrigPackets32(t *testing.T) {
	ct := encCtOrigPackets32(77)
	got, ok, err := ctOrigPackets(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("want ok=true")
	}
	if got != 77 {
		t.Fatalf("got %d want 77", got)
	}
}

func TestCtOrigPacketsNone(t *testing.T) {
	// Empty blob → ok=false
	got, ok, err := ctOrigPackets(nil)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("ok=true with empty blob")
	}
	if got != 0 {
		t.Fatalf("got %d want 0", got)
	}
}
