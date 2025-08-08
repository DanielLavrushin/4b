package processor

import (
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/mangle"
	nfqueue "github.com/florianl/go-nfqueue"
)

func TestCallback_SkipOwnMark(t *testing.T) {
	cfg := &config.Config{Mark: 1 << 15}
	cb := New(cfg)

	mark := uint32(cfg.Mark)
	a := &nfqueue.Attribute{Mark: &mark}
	if v := cb(a); v != nfqueue.NfAccept {
		t.Fatalf("got verdict %d want NfAccept", v)
	}
}

func TestCallback_EmptyPayload(t *testing.T) {
	cfg := &config.Config{}
	cb := New(cfg)

	empty := []byte{}
	a := &nfqueue.Attribute{Payload: &empty}
	if v := cb(a); v != nfqueue.NfAccept {
		t.Fatalf("got verdict %d want NfAccept", v)
	}
}

func TestCallback_ConntrackThreshold(t *testing.T) {
	cfg := &config.Config{ConnBytesLimit: 2}
	cb := New(cfg)

	// craft NFQA_CT with CTA_COUNTERS_ORIG.packets = 3 (exceeds limit)
	ct := encCtOrigPackets64(3)
	payload := []byte{0x01} // non-empty to avoid early accept path
	a := &nfqueue.Attribute{Ct: &ct, Payload: &payload}

	if v := cb(a); v != nfqueue.NfAccept {
		t.Fatalf("got verdict %d want NfAccept due to conntrack threshold", v)
	}
}

func TestCallback_ProcessPacketDrop(t *testing.T) {
	// stub processPacket to return VerdictDrop
	orig := processPacket
	processPacket = func(_ *config.Config, _ []byte) mangle.Verdict { return mangle.VerdictDrop }
	t.Cleanup(func() { processPacket = orig })

	cfg := &config.Config{}
	cb := New(cfg)

	pl := []byte{0xaa}
	a := &nfqueue.Attribute{Payload: &pl}
	if v := cb(a); v != nfqueue.NfDrop {
		t.Fatalf("got verdict %d want NfDrop", v)
	}
}

func TestCallback_ProcessPacketAccept(t *testing.T) {
	// stub to Accept (by returning VerdictContinue)
	orig := processPacket
	processPacket = func(_ *config.Config, _ []byte) mangle.Verdict { return mangle.VerdictContinue }
	t.Cleanup(func() { processPacket = orig })

	cfg := &config.Config{}
	cb := New(cfg)

	pl := []byte{0xbb}
	a := &nfqueue.Attribute{Payload: &pl}
	if v := cb(a); v != nfqueue.NfAccept {
		t.Fatalf("got verdict %d want NfAccept", v)
	}
}
