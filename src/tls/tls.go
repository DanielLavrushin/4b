package tls

import (
	"golang.org/x/crypto/cryptobyte"
)

func ExtractSNI(payload []byte) (hostname []byte, err error) {
	s := cryptobyte.String(payload)

	for !s.Empty() {
		// ---- TLS record header ----
		var ct uint8
		if !s.ReadUint8(&ct) { // content type
			return nil, errNotHello
		}
		// legacy_version (2 байта)
		if !s.Skip(2) {
			return nil, errNotHello
		}
		// record length
		var rlen uint16
		if !s.ReadUint16(&rlen) {
			return nil, errNotHello
		}
		if int(rlen) > len(s) {
			// на случай усечённого буфера занижаем до остатка
			rlen = uint16(len(s))
		}

		var rec cryptobyte.String
		if !s.ReadBytes((*[]byte)(&rec), int(rlen)) {
			return nil, errNotHello
		}

		// Интересны только Handshake‑рекорды
		if ct != tlsContentTypeHandshake {
			continue
		}

		// ---- Внутри рекорда может быть несколько Handshake сообщений ----
		rr := rec
		for !rr.Empty() {
			var hsType uint8
			if !rr.ReadUint8(&hsType) {
				break
			}
			var body cryptobyte.String
			if !rr.ReadUint24LengthPrefixed(&body) {
				break
			}

			if hsType != tlsHandshakeClientHello {
				continue
			}

			// ---- Разбор ClientHello (минимально необходимый) ----
			ch := body

			// legacy_version(2) + random(32)
			if !ch.Skip(2 + 32) {
				return nil, errNotHello
			}

			// session_id
			var sidLen uint8
			if !ch.ReadUint8(&sidLen) || !ch.Skip(int(sidLen)) {
				return nil, errNotHello
			}

			// cipher_suites
			var csLen uint16
			if !ch.ReadUint16(&csLen) || !ch.Skip(int(csLen)) {
				return nil, errNotHello
			}

			// compression_methods
			var cmLen uint8
			if !ch.ReadUint8(&cmLen) || !ch.Skip(int(cmLen)) {
				return nil, errNotHello
			}

			// extensions
			var exts cryptobyte.String
			if !ch.ReadUint16LengthPrefixed(&exts) {
				return nil, errNotHello
			}
			for !exts.Empty() {
				var et uint16
				if !exts.ReadUint16(&et) {
					return nil, errNotHello
				}
				var extData cryptobyte.String
				if !exts.ReadUint16LengthPrefixed(&extData) {
					return nil, errNotHello
				}
				if et != tlsExtServerName {
					continue
				}

				// SNI list
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
					hcopy := append([]byte(nil), host...)
					return hcopy, nil
				}
			}
		}
	}

	return nil, errNotHello
}
