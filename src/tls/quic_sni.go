// tls/quic_sni.go
package tls

import (
	"golang.org/x/crypto/cryptobyte"
)

func ExtractSNIFromQUIC(crypto []byte) ([]byte, error) {
	s := cryptobyte.String(crypto)

	// В CRYPTO могут идти несколько Handshake-сообщений подряд — сканируем все.
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

		// ---- Parse ClientHello ----
		ch := body
		if !ch.Skip(2 + 32) { // legacy_version + random
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
				if !sniList.ReadUint8(&nameType) || nameType != 0 { // host_name
					return nil, errNotHello
				}
				var host cryptobyte.String
				if !sniList.ReadUint16LengthPrefixed(&host) {
					return nil, errNotHello
				}
				if len(host) == 0 {
					return nil, errNotHello
				}
				// ВАЖНО: делаем копию, чтобы отвязаться от исходного буфера.
				hcopy := append([]byte(nil), host...)
				return hcopy, nil
			}
		}
	}
	return nil, errNotHello
}
