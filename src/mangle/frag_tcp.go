package mangle

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func tcpFrag(pkt []byte, payloadOffset int) (first, second []byte, err error) {
	var (
		ip4 layers.IPv4
		ip6 layers.IPv6
		tcp layers.TCP
		pld gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeIPv4, &ip4, &ip6, &tcp, &pld,
	)
	decoded := []gopacket.LayerType{}
	if err = parser.DecodeLayers(pkt, &decoded); err != nil {
		return nil, nil, err
	}

	// Choose which IP layer we actually populated
	var (
		ipLayer gopacket.SerializableLayer
		origIP4 = ip4.Version == 4
		baseSeq = tcp.Seq
		payload = []byte(pld)
	)
	if payloadOffset <= 0 || payloadOffset >= len(payload) {
		return nil, nil, errors.New("tcpFrag: offset outside payload")
	}

	firstPayload, secondPayload := payload[:payloadOffset], payload[payloadOffset:]

	build := func(data []byte, seq uint32) ([]byte, error) {
		tcpCopy := tcp
		tcpCopy.Seq = seq
		tcpCopy.SYN = false

		// reset checksums & lengths
		if origIP4 {
			ip4Copy := ip4
			ip4Copy.Length, ip4Copy.Checksum = 0, 0
			ipLayer = &ip4Copy
		} else {
			ip6Copy := ip6
			ip6Copy.Length = 0
			ipLayer = &ip6Copy
		}

		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(
			buf,
			gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			ipLayer, &tcpCopy, gopacket.Payload(data),
		); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	first, err = build(firstPayload, baseSeq)
	if err != nil {
		return
	}
	second, err = build(secondPayload, baseSeq+uint32(len(firstPayload)))
	return
}
