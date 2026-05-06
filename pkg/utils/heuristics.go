package utils

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/cespare/xxhash/v2"
)

// NormalByteDistribution represents a normalized frequency model of typical HTTP traffic.
// Higher values for 'a-z', '0-9', and common symbols like '&', '=', '/', '?'.
var NormalByteDistribution [256]float64

func init() {
	// Initialize with a baseline that favors human-readable web traffic
	for i := 0; i < 256; i++ {
		NormalByteDistribution[i] = 0.0001 // Base noise
	}
	// Alphanumeric
	for i := 'a'; i <= 'z'; i++ {
		NormalByteDistribution[i] = 0.04
	}
	for i := 'A'; i <= 'Z'; i++ {
		NormalByteDistribution[i] = 0.02
	}
	for i := '0'; i <= '9'; i++ {
		NormalByteDistribution[i] = 0.01
	}
	// Common web separators
	NormalByteDistribution[' '] = 0.05
	NormalByteDistribution['&'] = 0.02
	NormalByteDistribution['='] = 0.02
	NormalByteDistribution['/'] = 0.02
	NormalByteDistribution['?'] = 0.01
	NormalByteDistribution['.'] = 0.01
}

// CalculateKLDivergence measures the statistical "distance" from a normal traffic model.
// Higher values indicate the payload is structurally abnormal (e.g. obfuscated, binary, or non-English).
func CalculateKLDivergence(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	var counts [256]float64
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}

	divergence := 0.0
	length := float64(len(s))

	for i := 0; i < 256; i++ {
		if counts[i] > 0 {
			p := counts[i] / length
			q := NormalByteDistribution[i]
			divergence += p * math.Log2(p/q)
		}
	}

	return divergence
}

// FingerprintHeaders returns a fast non-cryptographic hash of the header keys.
func FingerprintHeaders(headers map[string][]string) string {
	if len(headers) == 0 {
		return "0"
	}

	// We sort the keys to ensure the fingerprint is deterministic despite map iteration order
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := xxhash.New()
	for _, k := range keys {
		h.WriteString(k)
		h.WriteString("|")
	}
	return fmt.Sprintf("%016x", h.Sum64())
}

// VerifyClientFingerprint performs a high-fidelity check for client impersonation.
// It returns a confidence score (0-100) where 100 means a definite imposter.
func VerifyClientFingerprint(method, ua string, headers map[string][]string) float64 {
	score := 0.0
	isChrome := strings.Contains(ua, "Chrome")
	hasClientHints := false

	// Check for Modern Client Hint Consistency
	for k := range headers {
		if strings.HasPrefix(k, "Sec-Ch-Ua") {
			hasClientHints = true
			break
		}
	}

	// Anomaly: UA claims to be modern Chrome but lacks Client Hints
	if isChrome && !hasClientHints && strings.Contains(ua, "Mozilla/5.0") {
		score += 40.0
	}

	// 2. Detect Forbidden/Leaked Bot Headers
	botHeaders := []string{"Proxy-Connection", "X-Scanner", "X-Waf-Bypass", "Acunetix-Aspect"}
	for _, bh := range botHeaders {
		if _, exists := headers[bh]; exists {
			score += 60.0
		}
	}

	// 3. Multi-Factor Semantic Validation
	// Browsers send a consistent "ensemble" of headers.
	browserEnsemble := []string{"Accept", "Accept-Language", "Accept-Encoding"}
	missingEnsemble := 0
	for _, h := range browserEnsemble {
		if _, exists := headers[h]; !exists {
			missingEnsemble++
		}
	}
	
	// Anomaly: Claims to be a browser but missing standard browser headers
	if strings.Contains(ua, "Mozilla") && missingEnsemble >= 2 {
		score += 35.0
	}

	// 4. Method-Header Inconsistency
	// Real browsers do not send Content-Type on GET requests.
	if method == "GET" {
		if _, hasCT := headers["Content-Type"]; hasCT {
			score += 50.0
		}
	}

	// 5. Inconsistent Values (e.g. Modern UA with Legacy Connection)
	var conn string
	if vals := headers["Connection"]; len(vals) > 0 {
		conn = strings.ToLower(vals[0])
	}
	if hasClientHints && conn == "keep-alive" {
		score += 15.0
	}

	return math.Min(score, 100.0)
}

func SampleString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	third := maxLen / 3
	var sb strings.Builder
	sb.Grow(maxLen)

	sb.WriteString(s[:third])
	mid := len(s) / 2
	sb.WriteString(s[mid-third/2 : mid+third/2])
	sb.WriteString(s[len(s)-third:])

	return sb.String()
}

func ScoreNgrams(s string) float64 {
	if len(s) < 2 {
		return 0
	}

	suspicion := 0.0

	for i := 0; i < len(s)-1; i++ {
		a, b := s[i], s[i+1]
		if (a < 32 && a != 9 && a != 10 && a != 13) || a > 126 {
			suspicion += 5.0
		}
		if isSpecial(a) && isSpecial(b) {
			suspicion += 2.0
		}
		if (a == '$' && b == '{') || (a == '<' && b == '?') {
			suspicion += 10.0
		}
	}

	return suspicion / float64(len(s))
}

func isSpecial(b byte) bool {
	return (b >= 33 && b <= 47) || (b >= 58 && b <= 64) || (b >= 91 && b <= 96) || (b >= 123 && b <= 126)
}
