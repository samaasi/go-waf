package utils

import (
    "html"
    "net/url"
    "strings"
    "unicode"

    "golang.org/x/text/unicode/norm"
    "sync"
)

var builderPool = sync.Pool{
	New: func() interface{} {
		return &strings.Builder{}
	},
}

// NormalizeString applies layered decoding and canonicalization to resist evasion.
// - Repeated URL decoding up to a small cap
// - HTML entity unescape
// - Unicode normalization (NFKC)
// - Remove zero-width and control characters
// - Map common homoglyphs to ASCII equivalents
func NormalizeString(s string) string {
	if s == "" {
		return ""
	}

	// URL decode repeatedly up to 3 times
	for i := 0; i < 3; i++ {
		if !strings.Contains(s, "%") {
			break
		}
		d, err := url.QueryUnescape(s)
		if err != nil || d == s {
			break
		}
		s = d
	}

	// HTML entities - only if ampersand is present
	if strings.Contains(s, "&") {
		s = html.UnescapeString(s)
	}

	// Unicode normalization - only if non-ascii is present
	hasNonAscii := false
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			hasNonAscii = true
			break
		}
	}
	if hasNonAscii {
		s = norm.NFKC.String(s)
	}

	b := builderPool.Get().(*strings.Builder)
	b.Reset()
	defer builderPool.Put(b)

	// Pre-grow buffer to avoid reallocations
	b.Grow(len(s))

	lastSpace := false
	for _, r := range s {
		// Combined filter and mapping pass
		if r < 32 { // Control characters
			if r == '\t' || r == '\n' || r == '\r' {
				if !lastSpace {
					b.WriteByte(' ')
					lastSpace = true
				}
			}
			continue
		}

		if r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\u2060' {
			continue
		}

		if unicode.IsSpace(r) {
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
			continue
		}

		lastSpace = false

		// Fast-path for ASCII
		if r <= 127 {
			b.WriteRune(r)
			continue
		}

		if unicode.IsControl(r) {
			continue
		}

		// Homoglyph mapping (limited set)
		switch r {
		case 'Ｕ':
			r = 'U'
		case 'Ｓ':
			r = 'S'
		case 'Ｅ':
			r = 'E'
		case 'Ｌ':
			r = 'L'
		case 'ｅ':
			r = 'e'
		case 'ｎ':
			r = 'n'
		case 'ｉ':
			r = 'i'
		case 'ｏ':
			r = 'o'
		case 'ｓ':
			r = 's'
		case 'ｃ':
			r = 'c'
		}
		b.WriteRune(r)
	}

	return b.String()
}

// ContainsCaseInsensitive checks if substr is within s, ignoring case.
func ContainsCaseInsensitive(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
