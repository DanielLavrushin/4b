package sni

import (
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/quic"
	"golang.org/x/crypto/cryptobyte"
)

func ParseQUICClientHelloSNI(payload []byte) (string, bool) {
	if !quic.IsInitial(payload) {
		return "", false
	}
	dcid := quic.ParseDCID(payload)
	plain, ok := quic.DecryptInitial(dcid, payload)
	if !ok {
		return "", false
	}
	crypto, ok := assembleSafe(dcid, plain)
	if !ok || len(crypto) == 0 {
		log.Tracef("QUIC: no CRYPTO frames")
		return "", false
	}
	host, err := extractSNIFromQUIC(crypto)
	if err != nil || host == nil || len(host) == 0 {
		return "", false
	}
	quic.ClearDCID(dcid)
	return string(host), true
}

func assembleSafe(dcid, plain []byte) ([]byte, bool) {
	defer func() { _ = recover() }()
	return quic.AssembleCrypto(dcid, plain)
}

func extractSNIFromQUIC(crypto []byte) ([]byte, error) {
	s := cryptobyte.String(crypto)
	for !s.Empty() {
		var hsType uint8
		if !s.ReadUint8(&hsType) {
			return nil, errNotHello
		}
		var body cryptobyte.String
		if !s.ReadUint24LengthPrefixed(&body) {
			return nil, errNotHello
		}
		if hsType != tlsHandshakeClientHello {
			continue
		}
		ch := body
		if !ch.Skip(2 + 32) {
			return nil, errNotHello
		}
		var sid, ciphers, comp, exts cryptobyte.String
		if !ch.ReadUint8LengthPrefixed(&sid) {
			return nil, errNotHello
		}
		if !ch.ReadUint16LengthPrefixed(&ciphers) {
			return nil, errNotHello
		}
		if !ch.ReadUint8LengthPrefixed(&comp) {
			return nil, errNotHello
		}
		if !ch.ReadUint16LengthPrefixed(&exts) {
			return nil, errNotHello
		}
		for !exts.Empty() {
			var typ uint16
			var extData cryptobyte.String
			if !exts.ReadUint16(&typ) || !exts.ReadUint16LengthPrefixed(&extData) {
				return nil, errNotHello
			}
			if typ != tlsExtServerName {
				continue
			}
			var sniList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sniList) {
				return nil, errNotHello
			}
			for !sniList.Empty() {
				var nameType uint8
				if !sniList.ReadUint8(&nameType) || nameType != 0 {
					return nil, errNotHello
				}
				var host cryptobyte.String
				if !sniList.ReadUint16LengthPrefixed(&host) {
					return nil, errNotHello
				}
				if len(host) == 0 {
					return nil, errNotHello
				}
				hcopy := append([]byte(nil), host...)
				return hcopy, nil
			}
		}
	}
	return nil, errNotHello
}
