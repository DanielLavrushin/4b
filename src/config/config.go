package config

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type Logging struct {
	Verbose    int
	Instaflush bool
	Syslog     bool
}

const (
	VerboseInfo = iota
	VerboseDebug
	VerboseTrace
)

const (
	FragStratTCP = iota
	FragStratIP
	FragStratNone
)

const (
	FakeStratNone     = 0
	FakeStratRandSeq  = 1 << 0
	FakeStratTTL      = 1 << 1
	FakeStratPastSeq  = 1 << 2
	FakeStratTCPCheck = 1 << 3
	FakeStratTCPMD5   = 1 << 4
	FakeStratUDPCheck = 1 << 5
)

const (
	UDPMODEDrop = iota
	UDPMODEFake
)

const (
	UDPFilterQuicDisabled = iota
	UDPFilterQuicAll
	UDPFilterQuicParsed
)

const (
	FakePayloadDefault = iota // use built-in FakeSNIPkt
	FakePayloadCustom         // use FakeCustomPkt
	FakePayloadRandom         // random blob (length-bounded)
)

type UDPDPortRange struct {
	Start uint16
	End   uint16
}

type Section struct {
	ID int

	SNIDomains        []string
	ExcludeSNIDomains []string
	AllDomains        uint

	TLSEnabled bool

	FragmentationStrategy int
	FragSNIReverse        bool
	FragSNIFaked          bool
	FakingStrategy        int
	FragMiddleSNI         bool
	FragSNIPos            int
	FragTwoStage          bool
	FakingTTL             uint8
	FakeSNI               bool
	FakeSNISeqLen         uint

	FakeSNIType int

	Seg2Delay  uint
	SynFake    bool
	SynFakeLen uint

	FakeSNIPkt    []byte
	FakeCustomPkt []byte

	FKWinSize     uint
	FakeSeqOffset int

	DPortFilter bool

	SNIDetection int

	UDPMode           int
	UDPFakeSeqLen     uint
	UDPFakeLen        uint
	UDPFakingStrategy int

	UDPDPortRange []UDPDPortRange
	UDPFilterQuic int

	prev *Section
	next *Section
}

type Config struct {
	QueueStartNum uint
	Threads       int
	UseGSO        bool
	UseIPv6       bool
	UseConntrack  bool
	Mark          uint
	Daemonize     bool
	NoClose       bool
	Syslog        bool
	Instaflush    bool

	ConnBytesLimit int

	Verbose int

	FirstSection *Section
	LastSection  *Section
}

var DefaultSection = Section{
	TLSEnabled:            true,
	FragSNIReverse:        true,
	FragmentationStrategy: FragStratTCP,
	FakingStrategy:        FakeStratPastSeq,
	FakingTTL:             8,
	FakeSNI:               true,
	FakeSNISeqLen:         1,
	FakeSNIType:           FakePayloadRandom,
	FragMiddleSNI:         true,
	FragSNIPos:            1,
	FragTwoStage:          true,
	FakeSeqOffset:         10000,
	DPortFilter:           true,
	SNIDetection:          0,
	UDPMode:               UDPMODEFake,
	UDPFakeSeqLen:         6,
	UDPFakeLen:            64,
	UDPFakingStrategy:     FakeStratNone,
	UDPFilterQuic:         UDPFilterQuicDisabled,
}

var DefaultConfig = Config{
	Threads:        1,
	QueueStartNum:  537,
	Mark:           1 << 15,
	UseIPv6:        true,
	ConnBytesLimit: 19,
	Verbose:        VerboseDebug,
	UseGSO:         true,
	UseConntrack:   false,
	Daemonize:      false,
	NoClose:        false,
	Syslog:         false,
	Instaflush:     false,
}

func NewSection(id int) *Section {
	s := DefaultSection // copy
	s.ID = id
	s.prev, s.next = nil, nil
	s.ensureFakePayload()
	return &s
}

func (c *Config) Sections() []*Section {
	var list []*Section
	for s := c.FirstSection; s != nil; s = s.next {
		list = append(list, s)
	}
	return list
}

func (s *Section) MatchesSNI(host string) bool {
	host = strings.ToLower(host)

	for _, ex := range s.ExcludeSNIDomains {
		ex = strings.ToLower(ex)
		if host == ex || strings.HasSuffix(host, "."+ex) {
			return false
		}
	}

	if s.AllDomains != 0 {
		return true
	}

	for _, dom := range s.SNIDomains {
		dom = strings.ToLower(dom)
		if host == dom || strings.HasSuffix(host, "."+dom) {
			return true
		}
	}
	return false
}

func hexToBytes(hexStr string) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		return nil, fmt.Errorf("odd hex length")
	}
	out := make([]byte, len(hexStr)/2)
	_, err := hex.Decode(out, []byte(hexStr))
	return out, err
}
