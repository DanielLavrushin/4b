package mangle

import (
	"math/rand"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
	------------------------------------------------------------------
	  Flags reproduced 1-to-1 from the C headers

--------------------------------------------------------------------
*/
const (
	fakeStratNone    = 0
	fakeStratRandSeq = 1 << iota
	fakeStratTTL
	fakeStratPastSeq
	fakeStratTCPCheck
	fakeStratTCPMD5 // inject TCP MD5 option (kind=19, len=18)
	fakeStratUDPCheck
)

/*
	------------------------------------------------------------------
	  A light-weight description of “what exactly to forge”.

--------------------------------------------------------------------
*/
type fakeType struct {
	SequenceLen uint   // how many identical packets per strategy
	Strategy    int    // OR-ed flags above
	RandSeqOff  int    // for PastSeq / RandSeq
	TTL         uint8  // for TTL
	Payload     []byte // data to inject (already chosen by caller)
	Seg2Delay   uint   // delay of the *real* second fragment
	WinOverride uint16 // window size override
}

func (ft fakeType) iterateStrategies(fn func(int)) {
	if ft.Strategy == fakeStratNone {
		fn(fakeStratNone)
		return
	}
	for flag := 1; flag <= ft.Strategy; flag <<= 1 {
		if ft.Strategy&flag != 0 {
			fn(flag)
		}
	}
}

func buildFake(pktTemplate *layers.TCP, ip4 *layers.IPv4, ip6 *layers.IPv6,
	payload []byte, flag int, seqBase uint32, ft fakeType) ([]byte, error) {

	tcp := *pktTemplate
	switch flag {
	case fakeStratRandSeq:
		tcp.Seq = seqBase + uint32(rand.Intn(ft.RandSeqOff+1))
	case fakeStratPastSeq:
		tcp.Seq = seqBase - uint32(ft.RandSeqOff)
	default:
		tcp.Seq = seqBase
	}

	if flag&fakeStratTCPCheck != 0 {
		tcp.Urgent++ // minimal checksum disturbance
	}

	if ft.WinOverride > 0 {
		tcp.Window = ft.WinOverride
	}

	// FAKE_STRAT_TCP_MD5SUM: inject MD5 option (kind=19, len=18) + 2 NOPs
	if ft.Strategy&fakeStratTCPMD5 != 0 {
		tcp.Options = append(tcp.Options,
			layers.TCPOption{OptionType: layers.TCPOptionKind(19), OptionLength: 18, OptionData: make([]byte, 16)},
			layers.TCPOption{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
			layers.TCPOption{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
		)
	}

	var ipL gopacket.SerializableLayer
	if ip4 != nil {
		ip := *ip4
		if flag&fakeStratTTL != 0 {
			ip.TTL = ft.TTL
		}
		ipL = &ip
	} else {
		ip := *ip6
		if flag&fakeStratTTL != 0 {
			ip.HopLimit = ft.TTL
		}
		ipL = &ip
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ipL, &tcp, gopacket.Payload(payload)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sendFakeSequence(sec *config.Section, ft fakeType,
	tcp *layers.TCP, ip4 *layers.IPv4, ip6 *layers.IPv6) {

	if ft.SequenceLen == 0 {
		return
	}

	// Precompute cap for random payload size (same bounds logic as before)
	randomPerPacket := sec.FakeSNIType == config.FakePayloadRandom
	randCap := 0
	if randomPerPacket {
		if len(ft.Payload) > 0 {
			randCap = len(ft.Payload)
		}
		if len(sec.FakeCustomPkt) > 0 && len(sec.FakeCustomPkt) < randCap {
			randCap = len(sec.FakeCustomPkt)
		}
		if randCap <= 0 || randCap > 1200 {
			randCap = 1200
		}
	}

	// Non-random payload is chosen once
	var payload []byte
	switch sec.FakeSNIType {
	case config.FakePayloadCustom:
		payload = sec.FakeCustomPkt
		if len(payload) == 0 {
			payload = ft.Payload
		}
	case config.FakePayloadRandom:
		// defer to per-packet generation below
	default:
		payload = ft.Payload
	}

	baseSeq := tcp.Seq

	send := func(raw []byte) {
		if ft.Seg2Delay == 0 {
			_ = sendRaw(raw)
		} else {
			_ = sendDelayed(raw, ft.Seg2Delay)
		}
	}

	ft.iterateStrategies(func(flag int) {
		for i := uint(0); i < ft.SequenceLen; i++ {
			// choose payload for this packet
			p := payload
			if randomPerPacket {
				p = make([]byte, 1+rand.Intn(randCap))
			}
			if p == nil {
				p = ft.Payload
			}

			raw, err := buildFake(tcp, ip4, ip6, p, flag, baseSeq, ft)
			if err == nil {
				send(raw)
			}

			if flag != fakeStratPastSeq && flag != fakeStratRandSeq {
				baseSeq += uint32(len(p)) // advance by actual per-packet length
			}
		}
	})
}

func fakeTypeFromSection(sec *config.Section) fakeType {
	return fakeType{
		SequenceLen: sec.FakeSNISeqLen,
		Strategy:    sec.FakingStrategy,
		RandSeqOff:  sec.FakeSeqOffset,
		TTL:         sec.FakingTTL,
		Payload:     sec.FakeSNIPkt,
		Seg2Delay:   sec.Seg2Delay,
		WinOverride: uint16(sec.FKWinSize),
	}
}

func chooseFakePayload(sec *config.Section, fallback []byte, maxLen int) []byte {
	var p []byte
	switch sec.FakeSNIType {
	case config.FakePayloadCustom:
		if len(sec.FakeCustomPkt) > 0 {
			p = sec.FakeCustomPkt
		}
	case config.FakePayloadRandom:
		// upper bound: prefer configured length(s), cap at ~1200
		n := len(fallback)
		if n <= 0 || n > 1200 {
			n = 1200
		}
		if maxLen > 0 && maxLen < n {
			n = maxLen
		}
		p = make([]byte, 1+rand.Intn(n))
	}
	if p == nil {
		p = fallback
		if maxLen > 0 && maxLen < len(p) {
			p = p[:maxLen]
		}
	}
	return p
}

func init() { rand.Seed(time.Now().UnixNano()) }
