package mangle

import (
	"math/rand"
	"time"

	"github.com/daniellavrushin/4b/config"
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
	fakeStratTCPMD5 // ⟵ still ignored (kernel-only in C)
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

func sendFakeSequence(ft fakeType,
	tcp *layers.TCP, ip4 *layers.IPv4, ip6 *layers.IPv6) {

	if ft.SequenceLen == 0 || len(ft.Payload) == 0 {
		return
	}
	baseSeq := tcp.Seq

	send := func(raw []byte) { // honours Seg2Delay exactly like C
		if ft.Seg2Delay == 0 {
			_ = SendRaw(raw)
		} else {
			_ = SendDelayed(raw, ft.Seg2Delay)
		}
	}

	/* ----  iterate strategy → sequence_len loop ---------- */
	ft.iterateStrategies(func(flag int) {
		for i := uint(0); i < ft.SequenceLen; i++ {
			raw, err := buildFake(tcp, ip4, ip6, ft.Payload,
				flag, baseSeq, ft)
			if err == nil {
				send(raw)
			}

			// C code bumps SEQ only for non-Rand/Past
			if flag != fakeStratPastSeq && flag != fakeStratRandSeq {
				baseSeq += uint32(len(ft.Payload))
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
	}
}

func init() { rand.Seed(time.Now().UnixNano()) }
