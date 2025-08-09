package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func TestParse_DomainFiles_MergeTrimDedupe(t *testing.T) {
	dir := t.TempDir()

	inc := filepath.Join(dir, "include.txt")
	exc := filepath.Join(dir, "exclude.txt")

	mustWrite := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	mustWrite(inc, `
# comment
EXAMPLE.com
foo.bar
foo.bar  # dup
; another comment
MiXeD.Case.Org
`)
	mustWrite(exc, `
evil.example
EVIL.EXAMPLE   # dup (case-insensitive)
bad.host
`)

	cfg := config.DefaultConfig
	args := []string{
		"--sni-domains", " Foo.com ,  BAR.com , ,",
		"--sni-domains-file", inc,
		"--exclude-domains", "  Bad.Host ",
		"--exclude-domains-file", exc,
	}

	sects, err := Parse(&cfg, args)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s := sects[0]

	// Lowercased + deduped + merged (order stable-ish after dedupe)
	wantInc := []string{"foo.com", "bar.com", "example.com", "foo.bar", "mixed.case.org"}
	if !reflect.DeepEqual(s.SNIDomains, wantInc) {
		t.Fatalf("SNIDomains got %v want %v", s.SNIDomains, wantInc)
	}

	wantExc := []string{"bad.host", "evil.example"}
	if !reflect.DeepEqual(s.ExcludeSNIDomains, wantExc) {
		t.Fatalf("ExcludeSNIDomains got %v want %v", s.ExcludeSNIDomains, wantExc)
	}
}

func TestParse_AllDomainsFlag(t *testing.T) {
	cfg := config.DefaultConfig
	args := []string{"--sni-domains", "all"}

	sects, err := Parse(&cfg, args)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s := sects[0]
	if s.AllDomains != 1 {
		t.Fatalf("AllDomains = %d, want 1", s.AllDomains)
	}
	if len(s.SNIDomains) != 0 {
		t.Fatalf("SNIDomains should be empty when AllDomains=1, got %v", s.SNIDomains)
	}
}

func TestParse_UDPFlags(t *testing.T) {
	cfg := config.DefaultConfig
	args := []string{
		"--udp-mode", "drop",
		"--udp-faking-strategy", "checksum",
		"--udp-filter-quic", "parse",
		"--udp-dport-filter", "1000-1002,2000,3000-3001",
		"--no-dport-filter",
	}

	sects, err := Parse(&cfg, args)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s := sects[0]

	if s.UDPMode != config.UDPMODEDrop {
		t.Fatalf("UDPMode=%d want %d", s.UDPMode, config.UDPMODEDrop)
	}
	if s.UDPFakingStrategy != config.FakeStratUDPCheck {
		t.Fatalf("UDPFakingStrategy=%d want %d", s.UDPFakingStrategy, config.FakeStratUDPCheck)
	}
	if s.UDPFilterQuic != config.UDPFilterQuicParsed {
		t.Fatalf("UDPFilterQuic=%d want %d", s.UDPFilterQuic, config.UDPFilterQuicParsed)
	}
	// --no-dport-filter overrides the ranges entirely
	if s.DPortFilter {
		t.Fatalf("DPortFilter should be disabled by --no-dport-filter")
	}
}

func TestParse_FakingStrategy_And_Window_TTLS(t *testing.T) {
	cfg := config.DefaultConfig
	args := []string{
		"--faking-strategy", "md5sum",
		"--faking-ttl", "33",
		"--fake-seq-offset", "777",
		"--fk-winsize", "1234",
		"--tls", "disabled",
	}

	sects, err := Parse(&cfg, args)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s := sects[0]
	if s.FakingStrategy != config.FakeStratTCPMD5 {
		t.Fatalf("FakingStrategy=%d want %d", s.FakingStrategy, config.FakeStratTCPMD5)
	}
	if s.FakingTTL != 33 {
		t.Fatalf("FakingTTL=%d want 33", s.FakingTTL)
	}
	if s.FakeSeqOffset != 777 {
		t.Fatalf("FakeSeqOffset=%d want 777", s.FakeSeqOffset)
	}
	if s.FKWinSize != 1234 {
		t.Fatalf("FKWinSize=%d want 1234", s.FKWinSize)
	}
	if s.TLSEnabled {
		t.Fatalf("TLSEnabled should be false with --tls disabled")
	}
}

func TestParse_CustomPayload_HexAndFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "payload.bin")
	data := []byte{0xde, 0xad, 0xbe, 0xef}
	if err := os.WriteFile(f, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// 1) hex
	cfg1 := config.DefaultConfig
	args1 := []string{"--fake-custom-payload", "48656c6c6f00"} // "Hello\x00"
	sects, err := Parse(&cfg1, args1)
	if err != nil {
		t.Fatalf("Parse hex: %v", err)
	}
	if got, want := sects[0].FakeCustomPkt, []byte("Hello\x00"); !reflect.DeepEqual(got, want) {
		t.Fatalf("FakeCustomPkt(hex)=%x want %x", got, want)
	}

	// 2) file
	cfg2 := config.DefaultConfig
	args2 := []string{"--fake-custom-payload-file", f}
	sects, err = Parse(&cfg2, args2)
	if err != nil {
		t.Fatalf("Parse file: %v", err)
	}
	if got, want := sects[0].FakeCustomPkt, data; !reflect.DeepEqual(got, want) {
		t.Fatalf("FakeCustomPkt(file)=%x want %x", got, want)
	}
}

func TestParse_Frag_And_SNI_Toggles(t *testing.T) {
	cfg := config.DefaultConfig
	args := []string{
		"--frag", "ip",
		"--frag-sni-reverse",
		"--frag-sni-faked",
		"--frag-middle-sni",
		"--frag-sni-pos", "3",
		"--synfake",
		"--synfake-len", "7",
		"--seg2delay", "55",
		"--sni-detection", "brute",
	}

	sects, err := Parse(&cfg, args)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s := sects[0]
	if s.FragmentationStrategy != config.FragStratIP {
		t.Fatalf("FragmentationStrategy=%d want %d", s.FragmentationStrategy, config.FragStratIP)
	}
	if !s.FragSNIReverse || !s.FragSNIFaked || !s.FragMiddleSNI {
		t.Fatalf("frag toggles not set: %+v", s)
	}
	if s.FragSNIPos != 3 {
		t.Fatalf("FragSNIPos=%d want 3", s.FragSNIPos)
	}
	if !s.SynFake || s.SynFakeLen != 7 {
		t.Fatalf("SynFake/SynFakeLen wrong: %v/%d", s.SynFake, s.SynFakeLen)
	}
	if s.Seg2Delay != 55 {
		t.Fatalf("Seg2Delay=%d want 55", s.Seg2Delay)
	}
	if s.SNIDetection != 1 { // brute
		t.Fatalf("SNIDetection=%d want 1", s.SNIDetection)
	}
}

func TestParse_QuicDrop_OverridesModeAndFilter(t *testing.T) {
	cfg := config.DefaultConfig
	args := []string{
		"--udp-mode", "fake",
		"--udp-filter-quic", "disabled",
		"--quic-drop",
	}

	sects, err := Parse(&cfg, args)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s := sects[0]
	if s.UDPMode != config.UDPMODEDrop {
		t.Fatalf("UDPMode=%d want %d", s.UDPMode, config.UDPMODEDrop)
	}
	if s.UDPFilterQuic != config.UDPFilterQuicAll {
		t.Fatalf("UDPFilterQuic=%d want %d", s.UDPFilterQuic, config.UDPFilterQuicAll)
	}
}

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
