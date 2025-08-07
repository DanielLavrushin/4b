package trie

// Matcher is a suffix-matcher for ASCII hostnames.
// It is *case-insensitive* and treats dots as separators.
type Matcher struct{ root node }

type node struct {
	leaf bool
	next [256]*node
}

// Add inserts one hostname.  “googlevideo.com” and “youtu.be” are OK.
// It lower-cases ASCII bytes and ignores trailing dots.
func (m *Matcher) Add(pat string) error {
	cur := &m.root
	for i := len(pat) - 1; i >= 0; i-- { // build backwards ⇒ suffix-tree
		b := pat[i]
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if cur.next[b] == nil {
			cur.next[b] = &node{}
		}
		cur = cur.next[b]
	}
	cur.leaf = true
	return nil
}

// Match scans s and reports whether any suffix in the tree appears.
// If mapToEnd==false we return as soon as *any* match is seen.
// If mapToEnd==true we only succeed if the match ends at the last byte.
func (m *Matcher) Match(s []byte, mapToEnd bool) (bool, int, int) {
	for i := 0; i < len(s); i++ {
		cur := &m.root
		for j := i; j < len(s); j++ {
			b := s[len(s)-1-j+i] // walk backwards
			if 'A' <= b && b <= 'Z' {
				b += 'a' - 'A'
			}
			cur = cur.next[b]
			if cur == nil {
				break
			}
			if cur.leaf {
				if !mapToEnd || j == len(s)-1 {
					return true, i, j - i + 1
				}
			}
		}
	}
	return false, 0, 0
}
