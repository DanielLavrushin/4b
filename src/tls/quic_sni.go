// tls/quic_sni.go
package tls

import "golang.org/x/crypto/cryptobyte"

func ExtractSNIFromQUIC(crypto []byte) (hostname []byte, err error) {
	s := cryptobyte.String(crypto)

	// QUIC CRYPTO stream starts with TLS Handshake, no record header.
	var hsType uint8
	if !s.ReadUint8(&hsType) || hsType != tlsHandshakeClientHello {
		return nil, errNotHello
	}
	var ch cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&ch) { // handshake body
		return nil, errNotHello
	}

	// Parse ClientHello body (same steps you already do after your record header)
	if !ch.Skip(2 + 32) { // legacy_version + random
		return nil, errNotHello
	}
	var sess cryptobyte.String
	if !ch.ReadUint8LengthPrefixed(&sess) { // session id
		return nil, errNotHello
	}
	var ciphers cryptobyte.String
	if !ch.ReadUint16LengthPrefixed(&ciphers) {
		return nil, errNotHello
	}
	var comp cryptobyte.String
	if !ch.ReadUint8LengthPrefixed(&comp) {
		return nil, errNotHello
	}

	var exts cryptobyte.String
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
			if !sniList.ReadUint8(&nameType) || nameType != 0 { // host_name
				return nil, errNotHello
			}
			var host cryptobyte.String
			if !sniList.ReadUint16LengthPrefixed(&host) {
				return nil, errNotHello
			}
			return host, nil
		}
	}
	return nil, errNotHello
}
