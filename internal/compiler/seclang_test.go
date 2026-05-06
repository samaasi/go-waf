package compiler

import (
	"testing"

	"github.com/samaasi/go-waf/internal/platform/logger"
)

func TestParseRule(t *testing.T) {
	comp := NewCompiler(logger.NewZapAdapter(logger.Init("info")))

	directive := `SecRule REQUEST_URI "@rx (?i)\b(select|union|insert|delete)\b" "id:1001,phase:2,deny,msg:'SQLi detected',t:lowercase,t:removeWhitespace"`

	rule, err := comp.ParseRule(directive, "test.conf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rule.Variable != "REQUEST_URI" {
		t.Errorf("expected variable REQUEST_URI, got %s", rule.Variable)
	}

	if rule.Operator != "@rx" {
		t.Errorf("expected operator @rx, got %s", rule.Operator)
	}

	if rule.ID != "1001" {
		t.Errorf("expected ID 1001, got %s", rule.ID)
	}

	if rule.Action != "block" {
		t.Errorf("expected Action block, got %s", rule.Action)
	}

	if len(rule.Transformations) != 2 || rule.Transformations[0] != "t:lowercase" {
		t.Errorf("expected transformations, got %v", rule.Transformations)
	}

	if rule.PreFilterKeyword != "select" && rule.PreFilterKeyword != "union" {
		t.Errorf("expected pre-filter keyword like 'select' or 'union', got %s", rule.PreFilterKeyword)
	}
}

func TestParseTokens(t *testing.T) {
	line := `SecRule REQUEST_URI "@rx malicious" "id:1"`
	tokens := parseTokens(line)
	if len(tokens) != 4 {
		t.Fatalf("expected 4 tokens, got %d", len(tokens))
	}
	if tokens[2] != "\"@rx malicious\"" {
		t.Errorf("expected quoted operator, got %s", tokens[2])
	}
}

func TestExtractPreFilterKeyword(t *testing.T) {
	comp := NewCompiler(nil)

	tests := []struct {
		operator string
		value    string
		expected string
	}{
		{"@streq", "admin", "admin"},
		{"@rx", `(?i)\b(script|iframe)\b`, "script"}, // iframe is also 6 chars, script is 6. either is fine depending on order. Our simple extraction finds script first and uses it. Wait, `script` is 6, `iframe` is 6. The logic `if len(m) > len(longest)` strictly requires greater, so it takes the first longest.
		{"@rx", `\.(ini|conf|log)`, "conf"},          // wait, ini is 3, conf is 4. -> conf
	}

	for _, tt := range tests {
		result := comp.ExtractPreFilterKeyword(tt.operator, tt.value)
		if result != tt.expected {
			t.Errorf("expected %s, got %s for %s %s", tt.expected, result, tt.operator, tt.value)
		}
	}
}
