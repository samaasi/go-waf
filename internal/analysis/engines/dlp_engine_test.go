package engines

import (
	"testing"
)

func TestDlpEngine_Luhn(t *testing.T) {
	tests := []struct {
		cc       string
		expected bool
	}{
		{"4111111111111111", true},  // Valid Visa
		{"4111111111111112", false}, // Invalid
		{"378282246310005", true},   // Valid Amex
		{"5105105105105100", true},  // Valid Mastercard
	}

	for _, tt := range tests {
		if isLuhnValid(tt.cc) != tt.expected {
			t.Errorf("isLuhnValid(%s) = %v, want %v", tt.cc, !tt.expected, tt.expected)
		}
	}
}

func TestDlpEngine_Patterns(t *testing.T) {
	e, _ := NewDlpEngine("")
	
	tests := []struct {
		body     string
		expected int
	}{
		{"My CC is 4111111111111111", 1},
		{"Not a CC 4111111111111112", 0},
		{"AWS key: AKIA1234567890ABCDEF", 1},
		{"Secret token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoyNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", 1},
	}

	for _, tt := range tests {
		events := e.InspectResponse([]byte(tt.body))
		if len(events) != tt.expected {
			t.Errorf("For body %q, expected %d events, got %d", tt.body, tt.expected, len(events))
		}
	}
}
