package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/daniellavrushin/4b/config"
	"github.com/daniellavrushin/4b/mangle"
	"github.com/daniellavrushin/4b/processor"
	"github.com/daniellavrushin/4b/queue"
	"github.com/daniellavrushin/4b/rawsock"
	"github.com/spf13/cobra"
)

var cfg = config.DefaultConfig

func main() {
	// create default section if the config is still empty
	if cfg.FirstSection == nil {
		s := config.NewSection(0)
		cfg.FirstSection = s
		cfg.LastSection = s
	}

	root := &cobra.Command{
		Use: "4b",
		RunE: func(cmd *cobra.Command, args []string) error {
			//------------------------------------------------------------
			// 1) open raw sockets so mangle can send forged packets back
			//------------------------------------------------------------
			raw4, raw6, err := rawsock.New(uint32(cfg.Mark))
			if err != nil {
				return err
			}
			mangle.SetRawSendFunc(func(pkt []byte) error {
				if mangle.IPVersion(pkt) == 6 {
					return raw6(pkt)
				}
				return raw4(pkt)
			})

			//------------------------------------------------------------
			// 2) start one nfqueue worker per configured thread
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
					return err
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
			return nil
		},
	}

	//------------------------------------------------------------
	// CLI flags (same ones you had, attached to the new root cmd)
	//------------------------------------------------------------
	root.Flags().IntVarP(&cfg.Verbose, "verbose", "v", 0, "Set verbosity level (0=info, 1=debug, 2=trace)")
	root.Flags().BoolVarP(&cfg.Instaflush, "instaflush", "i", false, "Enable instaflush mode")
	root.Flags().BoolVarP(&cfg.Syslog, "syslog", "s", false, "Enable syslog logging")
	root.Flags().BoolVar(&cfg.UseGSO, "gso", true, "Enable GSO handling")
	root.Flags().IntVarP(&cfg.Threads, "threads", "t", 1, "Number of NFQ threads")
	root.Flags().UintVar(&cfg.QueueStartNum, "queue", cfg.QueueStartNum, "First NFQ queue id")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
