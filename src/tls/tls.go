package tls

import (
	"github.com/daniellavrushin/b4/logx"
	"golang.org/x/crypto/cryptobyte"
)

func ExtractSNI(payload []byte) (hostname []byte, err error) {
	s := cryptobyte.String(payload)

	var ct uint8
	if !s.ReadUint8(&ct) || ct != tlsContentTypeHandshake {
		return nil, errNotHello
	}
	var legacyVersion uint16
	if !s.Skip(1) || !s.ReadUint16(&legacyVersion) { // skip 1 byte, read legacy_version
		return nil, errNotHello
	}
	var rec cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&rec) { // record payload
		return nil, errNotHello
	}
	var hsType uint8
	if !rec.ReadUint8(&hsType) || hsType != tlsHandshakeClientHello {
		return nil, errNotHello
	}
	if !rec.Skip(3) { // handshake length (24 bit) – we ignore it
		return nil, errNotHello
	}

	if !rec.Skip(2 + 32) { // legacy_version + random
		return nil, errNotHello
	}
	var sess cryptobyte.String
	if !rec.ReadUint8LengthPrefixed(&sess) { // session ID
		return nil, errNotHello
	}
	var ciphers cryptobyte.String
	if !rec.ReadUint16LengthPrefixed(&ciphers) { // cipher suites
		return nil, errNotHello
	}
	var comp cryptobyte.String
	if !rec.ReadUint8LengthPrefixed(&comp) { // compression
		return nil, errNotHello
	}

	var exts cryptobyte.String
	if !rec.ReadUint16LengthPrefixed(&exts) {
		return nil, errNotHello
	}
	for !exts.Empty() {
		var typ uint16
		var extData cryptobyte.String
		if !exts.ReadUint16(&typ) ||
			!exts.ReadUint16LengthPrefixed(&extData) {
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
			logx.Tracef("SNI host found: %s", host)
			return host, nil // first entry wins
		}
	}
	return nil, errNotHello
}
