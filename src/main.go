package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/daniellavrushin/4b/config"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "4b",
	RunE: func(cmd *cobra.Command, args []string) error {
		nfq, err := NewNFQueues(&cfg)
		if err != nil {
			return err
		}
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		go nfq.Run()
		<-sig
		nfq.Close()
		return nil
	},
}

var cfg = config.DefaultConfig

type NFQueues struct{}

func NewNFQueues(c *config.Config) (*NFQueues, error) {
	return &NFQueues{}, nil
}

func (n *NFQueues) Run() {}

func (n *NFQueues) Close() {}

func init() {
	rootCmd.Flags().IntVarP(&cfg.Verbose, "verbose", "v", 0, "Set verbosity level (0=info, 1=debug, 2=trace)")
	rootCmd.Flags().BoolVarP(&cfg.Instaflush, "instaflush", "i", false, "Enable instaflush mode")
	rootCmd.Flags().BoolVarP(&cfg.Syslog, "syslog", "s", false, "Enable syslog logging")
	rootCmd.Flags().BoolVar(&cfg.UseGSO, "gso", true, "Enable GSO handling")
	rootCmd.Flags().IntVarP(&cfg.Threads, "threads", "t", 1, "Number of NFQ threads")
	rootCmd.Flags().UintVar(&cfg.QueueStartNum, "queue", cfg.QueueStartNum, "First NFQ queue id")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func openRaw4(mark uint32) (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return -1, err
	}
	if mark != 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, int(mark)); err != nil {
			_ = syscall.Close(fd)
			return -1, err
		}
	}
	return fd, nil
}

// very small helper – no mutex needed if you run only one queue/thread;
// will add sync.Mutex to call it from many goroutines later...
func makeIPv4Sender(fd int) func([]byte) error {
	return func(pkt []byte) error {
		// dst address is pulled from IP header – no need to fill the port
		sa := &syscall.SockaddrInet4{}
		copy(sa.Addr[:], pkt[16:20]) // IPv4 dst is at offset 16
		return syscall.Sendto(fd, pkt, 0, sa)
	}
}
