package engines

import (
	"context"
	"net/url"
	"testing"

	"github.com/cloudflare/ahocorasick"
	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/internal/store"
)

func TestCRSLangEngine_PreFilter(t *testing.T) {
	mockStore := store.NewMockCollectionStore()
	engine := NewCRSLangEngine("", mockStore)
	engine.rules = []CRSLangRule{
		{
			ID:               "1001",
			Msg:              "Test Rule",
			Phase:            1,
			PreFilterKeyword: "malicious_keyword",
			Conditions: []struct {
				Operator        string   `yaml:"operator"`
				Variable        string   `yaml:"variable"`
				Value           string   `yaml:"value"`
				Transformations []string `yaml:"transformations"`
			}{
				{
					Operator: "@contains",
					Variable: "REQUEST_URI",
					Value:    "malicious_keyword",
				},
			},
		},
	}
	
	// manually initialize
	engine.keywords = []string{"malicious_keyword"}
	engine.aho = ahocorasick.NewStringMatcher(engine.keywords)

	tests := []struct {
		name     string
		req      *domain.WafRequest
		expected int
	}{
		{
			name: "Should match when keyword is present",
			req: &domain.WafRequest{
				Path:      "/test/malicious_keyword",
				QueryArgs: url.Values{},
			},
			expected: 1,
		},
		{
			name: "Should skip when keyword is missing",
			req: &domain.WafRequest{
				Path:      "/test/safe_path",
				QueryArgs: url.Values{},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := engine.Evaluate(context.Background(), tt.req, 1)
			if len(events) != tt.expected {
				t.Errorf("expected %d events, got %d", tt.expected, len(events))
			}
		})
	}
}

func TestCRSLangEngine_Transformations(t *testing.T) {
	engine := NewCRSLangEngine("", nil)
	
	tests := []struct {
		input     string
		transform string
		expected  string
	}{
		{"HELLO World", "t:lowercase", "hello world"},
		{"a b\tc\nd", "t:removeWhitespace", "abcd"},
		{"no_transform", "unknown", "no_transform"},
	}

	for _, tt := range tests {
		result := engine.applyTransformation(tt.input, tt.transform)
		if result != tt.expected {
			t.Errorf("expected %q, got %q", tt.expected, result)
		}
	}
}
