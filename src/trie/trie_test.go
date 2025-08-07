package trie

import "testing"

/* ---------- small helper ---------- */

func mustAdd(t *testing.T, m *Matcher, pat string) {
	t.Helper()
	if err := m.Add(pat); err != nil {
		t.Fatalf("Add(%q): %v", pat, err)
	}
}

/* ---------- tests ---------- */

func TestMatcher_BasicAndMapToEnd(t *testing.T) {
	m := NewMatcher()
	mustAdd(t, m, "example.com")
	mustAdd(t, m, "video.com")

	// mapToEnd = false → match anywhere in the string
	src := []byte("https://cdn.example.com/path")
	ok, off, l := m.Match(src, false)
	if !ok || string(src[off:off+l]) != "example.com" {
		t.Fatalf("want hit on example.com, got ok=%v off=%d len=%d", ok, off, l)
	}

	// mapToEnd = true → only succeed if suffix ends at last byte
	if ok, _, _ := m.Match([]byte("example.com"), true); !ok {
		t.Fatalf("should match exact suffix when mapToEnd=true")
	}
	if ok, _, _ := m.Match([]byte("example.com/extra"), true); ok {
		t.Fatalf("must NOT match when suffix isn’t at buffer end")
	}
}

func TestMatcher_CaseInsensitive(t *testing.T) {
	m := NewMatcher()
	mustAdd(t, m, "YouTube.COM")

	if ok, _, _ := m.Match([]byte("img.youtube.com"), false); !ok {
		t.Fatalf("matcher must ignore ASCII case")
	}
}

func TestMatcher_NoMatch(t *testing.T) {
	m := NewMatcher()
	mustAdd(t, m, "abc")

	if ok, _, _ := m.Match([]byte("defg"), false); ok {
		t.Fatalf("unexpected positive match")
	}
}

func TestMatcher_ByteInsertEqualsAdd(t *testing.T) {
	m := NewMatcher()
	m.Insert([]byte("foo.bar"))

	if ok, _, _ := m.Match([]byte("dns.foo.bar"), true); !ok {
		t.Fatalf("Insert([]byte) should behave like Add(string)")
	}
}
