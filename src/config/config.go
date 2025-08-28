package config

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/daniellavrushin/b4/log"
)

type Logging struct {
	Level      int
	Instaflush bool
	Syslog     bool
}

type Config struct {
	QueueStartNum  int
	Mark           uint
	ConnBytesLimit int

	Interface    string
	Logging      Logging
	SNIDomains   []string
	Threads      int
	UseGSO       bool
	UseConntrack bool
}

var DefaultConfig = Config{
	QueueStartNum:  537,
	Mark:           1 << 15, // 32768
	Threads:        4,
	ConnBytesLimit: 19,
	UseConntrack:   false,
	UseGSO:         false,
	Logging: Logging{
		Level:      int(log.LevelInfo),
		Instaflush: true,
		Syslog:     false,
	},
}

func (cfg *Config) ParseArgs(args []string) (*Config, error) {

	fs := flag.NewFlagSet("b4", flag.ContinueOnError)

	fs.BoolVar(&cfg.Logging.Instaflush, "instaflush", cfg.Logging.Instaflush, "Enable instant flushing")
	fs.BoolVar(&cfg.Logging.Syslog, "syslog", cfg.Logging.Syslog, "Enable syslog")

	fs.StringVar(&cfg.Interface, "iface", cfg.Interface, "Set network interface")
	fs.IntVar(&cfg.Threads, "threads", cfg.Threads, "Set number of threads")

	var (
		logLevel       = fs.String("log-level", "info", "Set log level")
		sniDomainsFile = fs.String("sni-domains-file", "", "Set SNI domains file")
	)

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	switch *logLevel {
	case "info":
		cfg.Logging.Level = int(log.LevelInfo)
	case "trace":
		cfg.Logging.Level = int(log.LevelTrace)
	case "debug":
		cfg.Logging.Level = int(log.LevelDebug)
	default:
		cfg.Logging.Level = int(log.LevelInfo)
	}
	log.Tracef("sni domains file: %q", *sniDomainsFile)
	if err := applyDomainFile(cfg, *sniDomainsFile); err != nil {
		return nil, fmt.Errorf("domain file error: %w", err)
	}

	return cfg, nil
}

func applyDomainFile(cfg *Config, includePath string) error {
	if includePath != "" {
		inc, err := readDomainFile(includePath)
		if err != nil {
			log.Errorf("read %q: %w", includePath, err)
			return err
		}
		cfg.SNIDomains = append(cfg.SNIDomains, inc...)
	}

	// Normalize + dedupe
	cfg.SNIDomains = dedupeLower(cfg.SNIDomains)
	log.Infof("Loaded SNI domains: %v", cfg.SNIDomains)
	return nil
}

func dedupeLower(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func readDomainFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		l := strings.ToLower(line)
		if strings.HasPrefix(l, "full:") {
			line = strings.TrimSpace(line[len("full:"):])
		} else if strings.HasPrefix(l, "domain:") {
			line = strings.TrimSpace(line[len("domain:"):])
		} else if strings.HasPrefix(l, "regexp:") {
			continue
		}
		if line == "" {
			continue
		}
		out = append(out, strings.ToLower(line))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
