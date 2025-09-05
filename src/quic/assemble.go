package quic

import (
	"sync"
)

type cbuf struct {
	mu   sync.Mutex
	data []byte
	mask []byte
	head int
}

type cryptoFrame struct {
	off uint64
	b   []byte
}

var (
	cmap sync.Map
)

func readVarint(b []byte) (val uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	prefix := b[0] >> 6
	l := 1 << prefix
	if len(b) < l {
		return 0, 0
	}
	val = uint64(b[0] & 0x3f)
	for i := 1; i < l; i++ {
		val = (val << 8) | uint64(b[i])
	}
	return val, l
}

func parseCryptoFrames(plain []byte) (out []cryptoFrame) {
	i := 0
	for i < len(plain) {
		t := plain[i]
		i++
		switch t {
		case 0x06:
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
		case 0x00:
			for i < len(plain) && plain[i] == 0x00 {
				i++
			}
		case 0x01:
		default:
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
	b.mu.Lock()
	defer b.mu.Unlock()
	end := off + len(p)
	b.ensure(end)
	copy(b.data[off:end], p)
	for i := off; i < end; i++ {
		b.mask[i] = 1
	}
	for b.head < len(b.mask) && b.mask[b.head] == 1 {
		b.head++
	}
}

func (b *cbuf) snapshot() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.head == 0 {
		return nil, false
	}
	out := make([]byte, b.head)
	copy(out, b.data[:b.head])
	return out, true
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
		buf = &cbuf{data: make([]byte, 0, 4096), mask: make([]byte, 0, 4096)}
		cmap.Store(key, buf)
	}
	for _, f := range frames {
		if f.off > 1<<20 {
			continue
		}
		buf.write(int(f.off), f.b)
	}
	return buf.snapshot()
}

func ClearDCID(dcid []byte) {
	if len(dcid) == 0 {
		return
	}
	cmap.Delete(string(dcid))
}
