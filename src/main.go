package main

import (
	"fmt"
	"os"
	"os/signal"
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

	logx.Infof("starting b4: queues from %d, threads=%d, gso=%v, conntrack=%v",
		cfg.QueueStartNum, cfg.Threads, cfg.UseGSO, cfg.UseConntrack)

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
			logx.Errorf("worker %d init failed: %v", id, err)
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
