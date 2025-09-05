package main

import (
	"bytes"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daniellavrushin/b4/afp"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/iptables"
	"github.com/daniellavrushin/b4/log"
)

func main() {
	cfg := config.DefaultConfig
	if _, err := cfg.ParseArgs(os.Args[1:]); err != nil {
		os.Exit(1)
	}
	initLogging(&cfg)
	log.Infof("starting B4...")
	log.Infof("Running with flags: %s", flagsSummary(os.Args[1:]))

	if !cfg.SkipIpTables {
		iptables.ClearRules(&cfg)
		if err := iptables.AddRules(&cfg); err != nil {
			log.Errorf("failed to add iptables rules: %v", err)
			os.Exit(1)
		}
	}

	var ifaces []string
	if cfg.Interface == "" || cfg.Interface == "*" {
		ifs, _ := net.Interfaces()
		for _, inf := range ifs {
			if inf.Flags&net.FlagUp == 0 {
				continue
			}
			if inf.Flags&net.FlagLoopback != 0 {
				continue
			}
			ifaces = append(ifaces, inf.Name)
		}
	} else {
		ifaces = []string{cfg.Interface}
	}

	var sniffers []*afp.Sniffer
	for _, name := range ifaces {
		sn, err := afp.NewSniffer(afp.Config{
			Iface:               name,
			SnapLen:             96 * 1024,
			FlowTTL:             10 * time.Second,
			MaxClientHelloBytes: 8192,
			Promisc:             true,
			OnTLSHost:           func(ft afp.FiveTuple, host string) {},
			OnQUICHost:          func(ft afp.FiveTuple, host string) {},
		})
		if err != nil {
			log.Errorf("AF_PACKET start failed on %s: %v", name, err)
			continue
		}
		sn.Run()
		sniffers = append(sniffers, sn)
		log.Infof("AF_PACKET listening on %s", name)
	}
	if len(sniffers) == 0 {
		log.Errorf("no interfaces to sniff")
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	for _, sn := range sniffers {
		sn.Close()
	}

	if !cfg.SkipIpTables {
		if err := iptables.ClearRules(&cfg); err != nil {
			log.Errorf("failed to clear iptables rules: %v", err)
		}
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
