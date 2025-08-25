package mangle

// IPv6 Extension Header IDs
const (
	ip6NextHopByHop = 0  // Hop-by-Hop Options
	ip6NextRouting  = 43 // Routing
	ip6NextFragment = 44 // Fragment (fixed 8 bytes)
	ip6NextAH       = 51 // Authentication Header (len in 32-bit words, incl. 2)
	ip6NextESP      = 50 // ESP (далее уже не разберём — отступаем)
	ip6NextDstOpts  = 60 // Destination Options
	ip6NextNoNext   = 59 // No Next Header
	ip6NextTCP      = 6  // TCP
	ip6HeaderLen    = 40
)

// splitTCP возвращает реальный TCP payload из сырого IP-пакета (IPv4/IPv6 + IPv6 EH).
func splitTCP(pkt []byte) ([]byte, bool) {
	if len(pkt) < 1 {
		return nil, false
	}
	ver := pkt[0] >> 4

	if ver == 4 {
		// IPv4
		if len(pkt) < 20 {
			return nil, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+20 {
			return nil, false
		}
		// Protocol == TCP?
		if pkt[9] != 6 {
			return nil, false
		}
		// IP total length (на случай GSO/усечений)
		tot := int(pkt[2])<<8 | int(pkt[3])
		if tot > len(pkt) {
			tot = len(pkt)
		}
		ipPayload := pkt[ihl:tot]
		if len(ipPayload) < 20 {
			return nil, false
		}
		doff := int((ipPayload[12] >> 4) * 4)
		if doff < 20 || doff > len(ipPayload) {
			return nil, false
		}
		return ipPayload[doff:], true
	}

	if ver == 6 {
		// IPv6 + возможные Extension Headers
		if len(pkt) < ip6HeaderLen {
			return nil, false
		}
		next := pkt[6]
		off := ip6HeaderLen

		// Пролистываем цепочку EH до TCP
		for {
			switch next {
			case ip6NextTCP:
				// Готовы читать TCP заголовок
				if len(pkt) < off+20 {
					return nil, false
				}
				doff := int((pkt[off+12] >> 4) * 4)
				if doff < 20 || off+doff > len(pkt) {
					return nil, false
				}
				return pkt[off+doff:], true

			case ip6NextNoNext:
				return nil, false // дальше ничего нет

			case ip6NextHopByHop, ip6NextRouting, ip6NextDstOpts:
				// Формат: NextHeader(1) HdrExtLen(1) ...; длина = (HdrExtLen+1)*8
				if len(pkt) < off+2 {
					return nil, false
				}
				nn := pkt[off] // следующий next-header
				extLen := int(pkt[off+1])
				l := (extLen + 1) * 8
				if l < 8 || len(pkt) < off+l {
					return nil, false
				}
				next = nn
				off += l

			case ip6NextFragment:
				// Fragment header фиксированной длины 8 байт: NextHeader(1), Reserved(1), Off/Flags(2), Id(4)
				if len(pkt) < off+8 {
					return nil, false
				}
				next = pkt[off] // следующий
				off += 8
				// Вторая и далее фрагменты не содержат TCP заголовка — но в NFQUEUE нам обычно приходит первый

			case ip6NextAH:
				// AH: NextHeader(1), PayloadLen(1) — длина = (PayloadLen+2)*4
				if len(pkt) < off+2 {
					return nil, false
				}
				nn := pkt[off]
				pl := int(pkt[off+1])
				l := (pl + 2) * 4
				if l < 8 || len(pkt) < off+l {
					return nil, false
				}
				next = nn
				off += l

			case ip6NextESP:
				// ESP — без явного NextHeader; дальше корректно не разберём
				return nil, false

			default:
				// неизвестный EH — безопасно выходим
				return nil, false
			}
		}
	}

	return nil, false
}
