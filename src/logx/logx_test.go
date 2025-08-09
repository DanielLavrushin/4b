package logx

import (
	"bytes"
	"strings"
	"testing"
)

func TestLevelGating_InfoVsTrace(t *testing.T) {
	var stderr bytes.Buffer
	Init(&stderr, LevelInfo, true)

	Tracef("hidden")
	Infof("hello %d", 123)

	if got := stderr.String(); !strings.Contains(got, "hello 123") {
		t.Fatalf("expected info message in stderr, got %q", got)
	}
	if strings.Contains(stderr.String(), "hidden") {
		t.Fatalf("trace should be gated at Info level")
	}

	// enable trace
	SetLevel(LevelTrace)
	Tracef("now visible")
	if !strings.Contains(stderr.String(), "now visible") {
		t.Fatalf("trace still hidden after SetLevel(Trace)")
	}
}

func TestAttachSyslog_Fanout(t *testing.T) {
	var stderr, sys bytes.Buffer
	Init(&stderr, LevelInfo, true)
	AttachSyslog(&sys)

	Infof("fanout")
	if !strings.Contains(stderr.String(), "fanout") {
		t.Fatalf("stderr missing message")
	}
	if !strings.Contains(sys.String(), "fanout") {
		t.Fatalf("syslog sink missing message")
	}
}

func TestInstaflush_BufferingToggle(t *testing.T) {
	var stderr bytes.Buffer
	Init(&stderr, LevelInfo, false) // buffered

	Infof("buffered-msg")
	if stderr.Len() != 0 {
		t.Fatalf("expected no bytes written yet (buffered), got %q", stderr.String())
	}

	// switching to instaflush should flush pending data
	SetInstaflush(true)
	if !strings.Contains(stderr.String(), "buffered-msg") {
		t.Fatalf("expected buffered content to flush on SetInstaflush(true)")
	}

	// now writes go through immediately
	Infof("direct")
	if !strings.Contains(stderr.String(), "direct") {
		t.Fatalf("expected direct write after instaflush")
	}
}
