package cli

import (
	"reflect"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func TestParse_BasicFlags(t *testing.T) {
	cfg := config.DefaultConfig // copy
	args := []string{
		"--queue-num", "1001",
		"--threads", "4",
		"--no-gso",
		"--packet-mark", "4096",
		"--sni-domains", "example.com,foo.bar",
		"--exclude-domains", "evil.example",
	}

	sects, err := Parse(&cfg, args)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// root‑scoped expectations
	if got, want := cfg.QueueStartNum, uint(1001); got != want {
		t.Fatalf("QueueStartNum = %d, want %d", got, want)
	}
	if got, want := cfg.Threads, 4; got != want {
		t.Fatalf("Threads = %d, want %d", got, want)
	}
	if cfg.UseGSO {
		t.Fatalf("UseGSO should be disabled by --no-gso")
	}
	if got, want := cfg.Mark, uint(4096); got != want {
		t.Fatalf("Mark = %d, want %d", got, want)
	}

	// section‑scoped expectations
	if len(sects) != 1 {
		t.Fatalf("expected 1 section, got %d", len(sects))
	}
	s := sects[0]
	if !reflect.DeepEqual(s.SNIDomains, []string{"example.com", "foo.bar"}) {
		t.Fatalf("SNIDomains not parsed correctly: %+v", s.SNIDomains)
	}
	if !reflect.DeepEqual(s.ExcludeSNIDomains, []string{"evil.example"}) {
		t.Fatalf("ExcludeSNIDomains not parsed correctly: %+v", s.ExcludeSNIDomains)
	}
}
