package utils

import (
	"math"
)

// CalculateEntropy returns the Shannon entropy of a string.
// Range: 0.0 (all characters same) to ~8.0 (completely random bytes).
// Typical English text is ~3.5 to 4.5.
// Random strings/Encrypted payloads often exceed 5.5.
func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, char := range s {
		freq[char]++
	}

	var entropy float64
	length := float64(len(s))

	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}
