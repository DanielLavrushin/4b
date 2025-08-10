package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/daniellavrushin/b4/cli"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/logx"
	"github.com/daniellavrushin/b4/mangle"
	"github.com/daniellavrushin/b4/processor"
	"github.com/daniellavrushin/b4/queue"
	"github.com/daniellavrushin/b4/rawsock"
)

func main() {
	cfg := config.DefaultConfig

	// 0) CLI first, so cfg.Verbose/Syslog/Instaflush are set.
	if _, err := cli.Parse(&cfg, os.Args[1:]); err != nil {
		os.Exit(1)
	}

	// 1) Init logging based on parsed flags.
	if err := initLogging(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "log init failed: %v\n", err)
		os.Exit(1)
	}

	logx.Infof("starting B4...")
	logx.Infof("Running with flags: %s", flagsSummary(&cfg))

	// 2) Open raw sockets
	raw4, raw6, err := rawsock.New(uint32(cfg.Mark))
	if err != nil {
		panic(err)
	}
	mangle.SetRawSendFunc(func(pkt []byte) error {
		if mangle.IPVersion(pkt) == 6 {
			return raw6(pkt)
		}
		return raw4(pkt)
	})

	mangle.SetDelayedSendFunc(func(pkt []byte, delayMs uint) error {
		// choose the correct raw socket based on IP version
		send := raw4
		if mangle.IPVersion(pkt) == 6 {
			// honor --no-ipv6 just like the C tool (don’t attempt v6 sends)
			if !cfg.UseIPv6 {
				return nil
			}
			send = raw6
		}

		if delayMs == 0 {
			return send(pkt)
		}
		// schedule the send; AfterFunc runs the callback on its own goroutine
		time.AfterFunc(time.Duration(delayMs)*time.Millisecond, func() { _ = send(pkt) })
		return nil
	})

	// 3) NFQUEUE workers
	cb := processor.New(&cfg)
	workers := make([]*queue.Worker, cfg.Threads)
	for i := 0; i < cfg.Threads; i++ {
		id := uint16(uint(cfg.QueueStartNum) + uint(i))
		w, err := queue.NewWorker(queue.Config{
			ID:            id,
			WithGSO:       cfg.UseGSO,
			WithConntrack: cfg.UseConntrack,
			FailOpen:      true,
		}, cb)
		if err != nil {
			fmt.Fprintf(os.Stderr, "NFQUEUE init failed for id %d: %v\n", id, err)
			os.Exit(1)
		}
		workers[i] = w
		go w.Run()
		logx.Tracef("worker %d started", id)
	}

	// 4) Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	logx.Infof("signal %s received, shutting down...", s)
	for _, w := range workers {
		w.Close()
	}
	logx.Infof("bye")
}

func initLogging(cfg *config.Config) error {
	var lvl logx.Level
	switch cfg.Verbose {
	case config.VerboseTrace:
		lvl = logx.LevelTrace
	case config.VerboseInfo:
		lvl = logx.LevelInfo
	default:
		lvl = logx.LevelError
	}
	logx.Init(os.Stderr, lvl, cfg.Instaflush)
	if cfg.Syslog {
		if err := logx.EnableSyslog("b4"); err != nil {
			// keep stderr logger and report the failure
			logx.Errorf("syslog enable failed: %v", err)
			// not fatal
		}
	}
	return nil
}

func flagsSummary(cfg *config.Config) string {
	sec := cfg.FirstSection
	if sec == nil {
		return ""
	}
	bool01 := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}

	frag := map[int]string{
		config.FragStratTCP:  "tcp",
		config.FragStratIP:   "ip",
		config.FragStratNone: "none",
	}[sec.FragmentationStrategy]

	fakeType := map[int]string{
		config.FakePayloadDefault: "default",
		config.FakePayloadCustom:  "custom",
		config.FakePayloadRandom:  "random",
	}[sec.FakeSNIType]

	sniDetect := map[int]string{0: "parse", 1: "brute"}[sec.SNIDetection]

	var strat []string
	if sec.FakingStrategy&config.FakeStratRandSeq != 0 {
		strat = append(strat, "randseq")
	}
	if sec.FakingStrategy&config.FakeStratTTL != 0 {
		strat = append(strat, "ttl")
	}
	if sec.FakingStrategy&config.FakeStratPastSeq != 0 {
		strat = append(strat, "pastseq")
	}
	if sec.FakingStrategy&config.FakeStratTCPCheck != 0 {
		strat = append(strat, "tcp_check")
	}
	if sec.FakingStrategy&config.FakeStratTCPMD5 != 0 {
		strat = append(strat, "md5sum")
	}
	stratS := "none"
	if len(strat) > 0 {
		stratS = strings.Join(strat, "+")
	}

	// We don't have a trie instance here, so print a domain count.
	sniSummary := "<none>"
	switch {
	case sec.AllDomains != 0:
		sniSummary = "<all>"
	case len(sec.SNIDomains) > 0:
		sniSummary = fmt.Sprintf("<%d domains>", len(sec.SNIDomains))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--queue-num=%d", cfg.QueueStartNum)
	fmt.Fprintf(&b, " --threads=%d", cfg.Threads)
	if cfg.Mark != 0 {
		fmt.Fprintf(&b, " --packet-mark=%d", cfg.Mark)
	}
	if cfg.Verbose == config.VerboseTrace {
		fmt.Fprintf(&b, " --trace")
	}
	fmt.Fprintf(&b, " --tls=%s", map[bool]string{true: "enabled", false: "disabled"}[sec.TLSEnabled])
	fmt.Fprintf(&b, " --frag=%s", frag)
	fmt.Fprintf(&b, " --frag-sni-reverse=%d", bool01(sec.FragSNIReverse))
	fmt.Fprintf(&b, " --frag-sni-faked=%d", bool01(sec.FragSNIFaked))
	fmt.Fprintf(&b, " --frag-middle-sni=%d", bool01(sec.FragMiddleSNI))
	fmt.Fprintf(&b, " --frag-sni-pos=%d", sec.FragSNIPos)
	fmt.Fprintf(&b, " --fk-winsize=%d", sec.FKWinSize)
	fmt.Fprintf(&b, " --fake-sni=%d", bool01(sec.FakeSNI))
	fmt.Fprintf(&b, " --fake-sni-seq-len=%d", sec.FakeSNISeqLen)
	fmt.Fprintf(&b, " --fake-sni-type=%s", fakeType)
	fmt.Fprintf(&b, " --faking-strategy=%s", stratS)
	fmt.Fprintf(&b, " --fake-seq-offset=%d", sec.FakeSeqOffset)
	fmt.Fprintf(&b, " --seg2delay=%d", sec.Seg2Delay)
	fmt.Fprintf(&b, " --sni-domains=%s", sniSummary)
	fmt.Fprintf(&b, " --sni-detection=%s", sniDetect)
	fmt.Fprintf(&b, " --synfake=%d", bool01(sec.SynFake))
	fmt.Fprintf(&b, " --udp-filter-quic=%s", map[int]string{
		config.UDPFilterQuicDisabled: "disabled",
		config.UDPFilterQuicAll:      "all",
		config.UDPFilterQuicParsed:   "parse",
	}[sec.UDPFilterQuic])
	return b.String()
}
