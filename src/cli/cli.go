package cli

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/daniellavrushin/4b/config"
)

// Parse fills cfg *in‑place*, creates new sections when --fbegin / --fend
// are encountered and returns the slice of *config.Section in the order
// they were defined on the command‑line.
func Parse(cfg *config.Config, args []string) ([]*config.Section, error) {
	// always start with the default section
	sec := cfg.FirstSection
	if sec == nil {
		sec = config.NewSection(0)
		cfg.FirstSection, cfg.LastSection = sec, sec
	}

	// define root‑scoped flags
	fs := pflag.NewFlagSet("4b", pflag.ContinueOnError)
	queueNum := fs.Uint("queue-num", cfg.QueueStartNum, "NFQUEUE id")
	threads := fs.Int("threads", cfg.Threads, "Number of NFQUEUE workers")
	silent := fs.Bool("silent", false, "Verbosity INFO")
	trace := fs.Bool("trace", false, "Verbosity TRACE")
	instaflush := fs.Bool("instaflush", cfg.Instaflush, "Unbuffered logging")
	noGSO := fs.Bool("no-gso", false, "Disable GSO handling")
	useConntrack := fs.Bool("use-conntrack", cfg.UseConntrack, "Enable conntrack support")
	noIPv6 := fs.Bool("no-ipv6", false, "Disable IPv6 raw socket")
	connbytesLimit := fs.Int("connbytes-limit", cfg.ConnBytesLimit, "Connbytes limit")
	daemonize := fs.Bool("daemonize", false, "Fork into background")
	syslog := fs.Bool("syslog", false, "Log via syslog")
	noclose := fs.Bool("noclose", false, "Don't redirect stdio when daemonised")
	pktMark := fs.Uint("packet-mark", cfg.Mark, "Packet mark")

	// section‑scoped flags (applied to *sec* at parse time)
	var (
		tls               = fs.String("tls", "enabled", "")
		fakeSNI           = fs.Bool("fake-sni", sec.FakeSNI, "")
		fakeSNISeqLen     = fs.Uint("fake-sni-seq-len", sec.FakeSNISeqLen, "")
		fakeSNIType       = fs.String("fake-sni-type", "default", "")
		fakeCustomPayload = fs.String("fake-custom-payload", "", "")
		fakeCustomFile    = fs.String("fake-custom-payload-file", "", "")
		fakingStrategy    = fs.String("faking-strategy", "randseq", "")
		fakingTTL         = fs.Uint8("faking-ttl", sec.FakingTTL, "")
		fakeSeqOffset     = fs.Int("fake-seq-offset", sec.FakeSeqOffset, "")
		frag              = fs.String("frag", "tcp", "")
		fragSNIR          = fs.Bool("frag-sni-reverse", sec.FragSNIReverse, "")
		fragSNIFaked      = fs.Bool("frag-sni-faked", sec.FragSNIFaked, "")
		fragMiddleSNI     = fs.Bool("frag-middle-sni", sec.FragMiddleSNI, "")
		fragSNIPos        = fs.Int("frag-sni-pos", sec.FragSNIPos, "")
		fkWinSize         = fs.Uint("fk-winsize", sec.FKWinSize, "")
		synfake           = fs.Bool("synfake", sec.SynFake, "")
		synfakeLen        = fs.Uint("synfake-len", sec.SynFakeLen, "")
		sniDetection      = fs.String("sni-detection", "parse", "")
		seg2delay         = fs.Uint("seg2delay", sec.Seg2Delay, "")
		sniDomains        = fs.String("sni-domains", "", "")
		excludeDomains    = fs.String("exclude-domains", "", "")
		udpMode           = fs.String("udp-mode", "fake", "")
		udpFakeSeqLen     = fs.Uint("udp-fake-seq-len", sec.UDPFakeSeqLen, "")
		udpFakeLen        = fs.Uint("udp-fake-len", sec.UDPFakeLen, "")
		udpDportFilter    = fs.String("udp-dport-filter", "", "")
		udpFakingStrategy = fs.String("udp-faking-strategy", "none", "")
		udpFilterQUIC     = fs.String("udp-filter-quic", "disabled", "")
		quicDrop          = fs.Bool("quic-drop", false, "")
		noDPortFilter     = fs.Bool("no-dport-filter", !sec.DPortFilter, "")
	)

	// dummy section delimiters recognised manually
	fs.Bool("fbegin", false, "")
	fs.Bool("fend", false, "")

	// parse
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// -------- root‑scoped stuff
	cfg.QueueStartNum = *queueNum
	cfg.Threads = *threads
	cfg.Instaflush = *instaflush
	cfg.UseConntrack = *useConntrack
	if *silent {
		cfg.Verbose = config.VerboseInfo
	}
	if *trace {
		cfg.Verbose = config.VerboseTrace
	}
	if *noGSO {
		cfg.UseGSO = false
	}
	if *noIPv6 {
		cfg.UseIPv6 = false
	}
	cfg.ConnBytesLimit = *connbytesLimit
	cfg.Daemonize = *daemonize
	cfg.NoClose = *noclose
	cfg.Syslog = *syslog
	cfg.Mark = *pktMark

	// -------- section‑scoped stuff (first / default section only)

	sec.TLSEnabled = (*tls == "enabled")
	sec.FakeSNI = *fakeSNI
	sec.FakeSNISeqLen = *fakeSNISeqLen
	switch *fakeSNIType {
	case "default":
		sec.FakeSNIType = 0
	case "custom":
		sec.FakeSNIType = 1
	case "random":
		sec.FakeSNIType = 2
	}
	if *fakeCustomPayload != "" {
		b, err := hex.DecodeString(*fakeCustomPayload)
		if err != nil {
			return nil, fmt.Errorf("bad --fake-custom-payload: %w", err)
		}
		sec.FakeCustomPkt = b
	}
	if *fakeCustomFile != "" {
		b, err := os.ReadFile(*fakeCustomFile)
		if err != nil {
			return nil, err
		}
		sec.FakeCustomPkt = b
	}
	switch *fakingStrategy {
	case "randseq":
		sec.FakingStrategy = config.FakeStratRandSeq
	case "ttl":
		sec.FakingStrategy = config.FakeStratTTL
	case "tcp_check":
		sec.FakingStrategy = config.FakeStratTCPCheck
	case "pastseq":
		sec.FakingStrategy = config.FakeStratPastSeq
	case "md5sum":
		sec.FakingStrategy = config.FakeStratTCPMD5
	}
	sec.FakingTTL = *fakingTTL
	sec.FakeSeqOffset = *fakeSeqOffset

	switch *frag {
	case "tcp":
		sec.FragmentationStrategy = config.FragStratTCP
	case "ip":
		sec.FragmentationStrategy = config.FragStratIP
	case "none":
		sec.FragmentationStrategy = config.FragStratNone
	}
	sec.FragSNIReverse = *fragSNIR
	sec.FragSNIFaked = *fragSNIFaked
	sec.FragMiddleSNI = *fragMiddleSNI
	sec.FragSNIPos = *fragSNIPos
	sec.FKWinSize = *fkWinSize
	sec.SynFake = *synfake
	sec.SynFakeLen = *synfakeLen
	sec.Seg2Delay = *seg2delay
	switch *sniDetection {
	case "parse":
		sec.SNIDetection = 0
	case "brute":
		sec.SNIDetection = 1
	}
	if *sniDomains != "" {
		if *sniDomains == "all" {
			sec.AllDomains = 1
		} else {
			sec.SNIDomains = strings.Split(*sniDomains, ",")
		}
	}
	if *excludeDomains != "" {
		sec.ExcludeSNIDomains = strings.Split(*excludeDomains, ",")
	}
	// UDP / QUIC
	switch *udpMode {
	case "drop":
		sec.UDPMode = config.UDPMODEDrop
	case "fake":
		sec.UDPMode = config.UDPMODEFake
	}
	sec.UDPFakeSeqLen = *udpFakeSeqLen
	sec.UDPFakeLen = *udpFakeLen
	if *udpDportFilter != "" {
		sec.DPortFilter = true
		for _, rng := range strings.Split(*udpDportFilter, ",") {
			if dash := strings.IndexRune(rng, '-'); dash >= 0 {
				// range a-b
				sec.UDPDPortRange = append(sec.UDPDPortRange, config.UDPDPortRange{
					Start: uint16(parseU16(rng[:dash])),
					End:   uint16(parseU16(rng[dash+1:])),
				})
			} else {
				p := parseU16(rng)
				sec.UDPDPortRange = append(sec.UDPDPortRange, config.UDPDPortRange{Start: p, End: p})
			}
		}
	}
	switch *udpFakingStrategy {
	case "checksum":
		sec.UDPFakingStrategy = config.FakeStratUDPCheck
	case "ttl":
		sec.UDPFakingStrategy = config.FakeStratTTL
	case "none":
		sec.UDPFakingStrategy = config.FakeStratNone
	}
	switch *udpFilterQUIC {
	case "disabled":
		sec.UDPFilterQuic = config.UDPFilterQuicDisabled
	case "all":
		sec.UDPFilterQuic = config.UDPFilterQuicAll
	case "parse":
		sec.UDPFilterQuic = config.UDPFilterQuicParsed
	}
	if *quicDrop {
		sec.UDPMode = config.UDPMODEDrop
		sec.UDPFilterQuic = config.UDPFilterQuicAll
	}
	if *noDPortFilter {
		sec.DPortFilter = false
	}

	return cfg.Sections(), nil
}

func parseU16(s string) uint16 {
	var v uint16
	fmt.Sscanf(s, "%d", &v)
	return v
}
