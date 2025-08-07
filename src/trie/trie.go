package trie

type Matcher struct{ root node }

func NewMatcher() *Matcher { return &Matcher{} }

func (m *Matcher) Insert(b []byte) {
	_ = m.Add(string(b))
}

type node struct {
	leaf bool
	next [256]*node
}

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

// If mapToEnd==false we return as soon as *any* match is seen.
// If mapToEnd==true we only succeed if the match ends at the last byte.
func (m *Matcher) Match(s []byte, mapToEnd bool) (bool, int, int) {
	// Scan all possible *end* positions (right‑to‑left),
	// then walk the trie backwards from each end.
	for end := len(s) - 1; end >= 0; end-- {
		cur := &m.root
		for j := end; j >= 0; j-- {
			b := s[j]
			if 'A' <= b && b <= 'Z' {
				b += 'a' - 'A'
			}
			cur = cur.next[b]
			if cur == nil {
				break // this path can’t match; move end‑pointer leftwards
			}
			if cur.leaf {
				if !mapToEnd || end == len(s)-1 {
					return true, j, end - j + 1
				}
			}
		}
	}
	return false, 0, 0
}
