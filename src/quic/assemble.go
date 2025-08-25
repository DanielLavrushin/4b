package quic

import (
	"sync"
)

// --- внутренние типы ---

type cbuf struct {
	data []byte // накопленный CRYPTO поток
	mask []byte // 0/1: байт заполнен?
	head int    // длина непрерывного заполненного префикса [0:head)
}

type cryptoFrame struct {
	off uint64
	b   []byte
}

var (
	cmap sync.Map // key = string(DCID), val = *cbuf
)

// --- вспомогательные функции ---

// QUIC varint: первые 2 бита = длина (1,2,4,8), остальные биты + следующие байты = значение (big-endian).
func readVarint(b []byte) (val uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	prefix := b[0] >> 6
	l := 1 << prefix // 1,2,4,8
	if len(b) < l {
		return 0, 0
	}
	val = uint64(b[0] & 0x3f)
	for i := 1; i < l; i++ {
		val = (val << 8) | uint64(b[i])
	}
	return val, l
}

// вытащить CRYPTO-фреймы из расшифрованного Initial
func parseCryptoFrames(plain []byte) (out []cryptoFrame) {
	i := 0
	for i < len(plain) {
		t := plain[i]
		i++
		switch t {
		case 0x06: // CRYPTO
			off, n := readVarint(plain[i:])
			if n == 0 {
				return
			}
			i += n
			ln, n2 := readVarint(plain[i:])
			if n2 == 0 || int(ln) > len(plain)-i-n2 {
				return
			}
			i += n2
			out = append(out, cryptoFrame{off: off, b: plain[i : i+int(ln)]})
			i += int(ln)

		case 0x00: // PADDING — возможна серия
			for i < len(plain) && plain[i] == 0x00 {
				i++
			}
		case 0x01: // PING
			// нет полей
		default:
			// как в C: встретили чужой тип — завершаем
			return
		}
	}
	return
}

func (b *cbuf) ensure(n int) {
	if n <= len(b.data) {
		return
	}
	nd := make([]byte, n)
	copy(nd, b.data)
	b.data = nd

	nm := make([]byte, n)
	copy(nm, b.mask)
	b.mask = nm

	if b.head > n {
		b.head = n
	}
}

func (b *cbuf) write(off int, p []byte) {
	end := off + len(p)
	b.ensure(end)
	copy(b.data[off:end], p)
	for i := off; i < end; i++ {
		b.mask[i] = 1
	}
	// обновить head до первого незаполненного
	for b.head < len(b.mask) && b.mask[b.head] == 1 {
		b.head++
	}
}

func AssembleCrypto(dcid, plain []byte) ([]byte, bool) {
	if len(dcid) == 0 || len(plain) == 0 {
		return nil, false
	}
	key := string(dcid)

	frames := parseCryptoFrames(plain)
	if len(frames) == 0 {
		return nil, false
	}

	var buf *cbuf
	if v, ok := cmap.Load(key); ok {
		buf = v.(*cbuf)
	} else {
		buf = &cbuf{data: make([]byte, 0, 4096), mask: make([]byte, 0, 4096), head: 0}
		cmap.Store(key, buf)
	}

	for _, f := range frames {
		if f.off > 1<<20 { // sanity (1 MiB): защитимся от мусора
			continue
		}
		buf.write(int(f.off), f.b)
	}

	if buf.head == 0 {
		return nil, false
	}
	// Возвращать можно «живой» срез — парсер SNI копирует host.
	return buf.data[:buf.head], true
}
