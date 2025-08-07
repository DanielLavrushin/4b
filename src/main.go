package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/daniellavrushin/4b/cli"
	"github.com/daniellavrushin/4b/config"
	"github.com/daniellavrushin/4b/mangle"
	"github.com/daniellavrushin/4b/processor"
	"github.com/daniellavrushin/4b/queue"
	"github.com/daniellavrushin/4b/rawsock"
)

func main() {
	cfg := config.DefaultConfig

	// Parse CLI — will exit with error message itself on bad args
	if _, err := cli.Parse(&cfg, os.Args[1:]); err != nil {
		os.Exit(1)
	}

	//------------------------------------------------------------
	// 1) open raw sockets
	//------------------------------------------------------------
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

	//------------------------------------------------------------
	// 2) start NFQUEUE workers
	//------------------------------------------------------------
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
			panic(err)
		}
		workers[i] = w
		go w.Run()
	}

	//------------------------------------------------------------
	// 3) wait for SIGINT / SIGTERM
	//------------------------------------------------------------
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	for _, w := range workers {
		w.Close()
	}
}
