package main

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/iptables"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/nfq"
)

func main() {
	cfg := config.DefaultConfig
	if _, err := cfg.ParseArgs(os.Args[1:]); err != nil {
		os.Exit(1)
	}
	initLogging(&cfg)
	log.Infof("starting B4...")
	log.Infof("Running with flags: %s", flagsSummary(os.Args[1:]))

	iptables.ClearRules(&cfg)
	if err := iptables.AddRules(&cfg); err != nil {
		log.Errorf("failed to add iptables rules: %v", err)
		os.Exit(1)
	}

	cb := nfq.MakeCallback(&cfg)
	workers := make([]*nfq.Worker, cfg.Threads)
	for i := 0; i < cfg.Threads; i++ {
		id := uint16(uint(cfg.QueueStartNum) + uint(i))
		w, err := nfq.NewWorker(nfq.Config{
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
		log.Tracef("worker %d started", id)
	}

	// 4) Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Infof("signal %s received, shutting down...", s)
	for _, w := range workers {
		w.Close()
	}

	if err := iptables.ClearRules(&cfg); err != nil {
		log.Errorf("failed to clear iptables rules: %v", err)
	}
	log.Infof("bye")
}

func initLogging(cfg *config.Config) error {
	log.Init(os.Stderr, log.Level(cfg.Logging.Level), cfg.Logging.Instaflush)
	if cfg.Logging.Syslog {
		if err := log.EnableSyslog("b4"); err != nil {
			log.Errorf("syslog enable failed: %v", err)
		}
	}
	return nil
}

func flagsSummary(args []string) string {
	var buf bytes.Buffer
	for i, arg := range args {
		if i > 0 {
			buf.WriteString(" ")
		}
		buf.WriteString(arg)
	}
	return buf.String()
}
