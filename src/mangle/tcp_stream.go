package mangle

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

type tbuf struct {
	mu      sync.Mutex
	base    uint32
	data    []byte
	mask    []byte
	head    int
	lastUse time.Time
}

func (b *tbuf) ensure(n int) {
	if n <= len(b.data) {
		return
	}
	old := len(b.data)
	nd := make([]byte, n)
	copy(nd, b.data)
	b.data = nd
	nm := make([]byte, n)
	copy(nm, b.mask)
	b.mask = nm
	if b.head < old {
	} else if b.head > n {
		b.head = n
	}
}

func (b *tbuf) insert(seq uint32, p []byte) {
	if len(p) == 0 {
		return
	}
	if b.data == nil {
		b.base = seq
		b.ensure(len(p))
		copy(b.data, p)
		for i := 0; i < len(p); i++ {
			b.mask[i] = 1
		}
		b.head = advanceHead(b.mask, b.head)
		b.lastUse = time.Now()
		return
	}
	if lessSeq(seq, b.base) {
		return
	}
	off := int(seq - b.base)
	need := off + len(p)
	b.ensure(need)
	copy(b.data[off:off+len(p)], p)
	for i := 0; i < len(p); i++ {
		b.mask[off+i] = 1
	}
	if off <= b.head {
		b.head = advanceHead(b.mask, b.head)
	}
	b.lastUse = time.Now()
}

func advanceHead(mask []byte, from int) int {
	i := from
	for i < len(mask) && mask[i] == 1 {
		i++
	}
	return i
}

func lessSeq(a, b uint32) bool {
	return (a - b) > 0x80000000
}

func (b *tbuf) contiguous() []byte {
	if b.head <= 0 {
		return nil
	}
	return b.data[:b.head]
}

var tcpMap sync.Map

func flowKey(ip4 *layers.IPv4, ip6 *layers.IPv6, tcp *layers.TCP) string {
	if ip4 != nil {
		return fmt.Sprintf("4:%s:%d>%s:%d", ip4.SrcIP.String(), tcp.SrcPort, ip4.DstIP.String(), tcp.DstPort)
	}
	if ip6 != nil {
		return fmt.Sprintf("6:%s:%d>%s:%d", ip6.SrcIP.String(), tcp.SrcPort, ip6.DstIP.String(), tcp.DstPort)
	}
	return "?"
}

func tcpAssemblePrefix(tcp *layers.TCP, ip4 *layers.IPv4, ip6 *layers.IPv6, payload []byte) (prefix []byte, base uint32, ok bool) {
	key := flowKey(ip4, ip6, tcp)
	v, _ := tcpMap.LoadOrStore(key, &tbuf{})
	tb := v.(*tbuf)
	tb.mu.Lock()
	tb.insert(tcp.Seq, payload)
	pfx := tb.contiguous()
	b := tb.base
	tb.mu.Unlock()
	if len(pfx) == 0 {
		return nil, 0, false
	}
	return pfx, b, true
}

func tcpStreamDelete(tcp *layers.TCP, ip4 *layers.IPv4, ip6 *layers.IPv6) {
	key := flowKey(ip4, ip6, tcp)
	tcpMap.Delete(key)
}

func tcpStreamGC(maxAge time.Duration, maxSize int) {
	now := time.Now()
	tcpMap.Range(func(k, v any) bool {
		tb := v.(*tbuf)
		tb.mu.Lock()
		expire := now.Sub(tb.lastUse) > maxAge || len(tb.data) > maxSize
		tb.mu.Unlock()
		if expire {
			tcpMap.Delete(k)
		}
		return true
	})
}
