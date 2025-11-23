package utils

import (
    "html"
    "net/url"
    "strings"
    "unicode"

    "golang.org/x/text/unicode/norm"
)

// NormalizeString applies layered decoding and canonicalization to resist evasion.
// - Repeated URL decoding up to a small cap
// - HTML entity unescape
// - Unicode normalization (NFKC)
// - Remove zero-width and control characters
// - Map common homoglyphs to ASCII equivalents
func NormalizeString(s string) string {
    // URL decode repeatedly up to 3 times to avoid decoding bombs
    for i := 0; i < 3; i++ {
        d, err := url.QueryUnescape(s)
        if err != nil {
            break
        }
        if d == s {
            break
        }
        s = d
    }

    // HTML entities
    s = html.UnescapeString(s)

    // Unicode normalization
    s = norm.NFKC.String(s)

    // Remove zero-width and control chars; normalize whitespace to single spaces
    b := strings.Builder{}
    lastSpace := false
    for _, r := range s {
        // Filter out control and non-spacing marks commonly used for obfuscation
        if unicode.IsControl(r) {
            continue
        }
        switch r {
        case '\u200B', '\u200C', '\u200D', '\u2060': // zero-width characters
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
        // Homoglyph mapping (limited set)
        switch r {
        case 'Ｕ': r = 'U'
        case 'Ｓ': r = 'S'
        case 'Ｅ': r = 'E'
        case 'Ｌ': r = 'L'
        case 'ｅ': r = 'e'
        case 'ｎ': r = 'n'
        case 'ｉ': r = 'i'
        case 'ｏ': r = 'o'
        case 'ｓ': r = 's'
        case 'ｃ': r = 'c'
        }
        b.WriteRune(r)
    }
    return b.String()
}