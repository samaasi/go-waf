package engines

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"go-waf/internal/domain"
	"go-waf/internal/middleware"

	"github.com/cloudflare/ahocorasick"
)

// FastMatchEngine handles massive keyword lists using the Aho-Corasick algorithm.
type FastMatchEngine struct {
	matcher *ahocorasick.Matcher
	rules   []KeywordRule
}

// KeywordRule now includes JSON tags for loading
type KeywordRule struct {
	Pattern     string          `json:"pattern"`
	Severity    domain.Severity `json:"severity"`
	Description string          `json:"description"`
}

// NewFastMatchEngine loads rules from a file and builds the Aho-Corasick matcher.
func NewFastMatchEngine(rulePath string) (*FastMatchEngine, error) {
	rules, err := loadRulesFromJSON(rulePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load fast-match rules: %w", err)
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules found in %s", rulePath)
	}

	patterns := make([]string, len(rules))
	for i := range rules {
		// Force upper case in memory, even if JSON is lower
		rules[i].Pattern = strings.ToUpper(rules[i].Pattern)
		patterns[i] = rules[i].Pattern
	}

	matcher := ahocorasick.NewStringMatcher(patterns)

	return &FastMatchEngine{
		matcher: matcher,
		rules:   rules,
	}, nil
}

func (e *FastMatchEngine) ID() string                { return "fast-match" }
func (e *FastMatchEngine) Name() string              { return "Aho-Corasick Scanner" }
func (e *FastMatchEngine) Tags() []string            { return []string{"fast", "pre-filter", "dfa"} }
func (e *FastMatchEngine) Severity() domain.Severity { return domain.SeverityMedium }

func (e *FastMatchEngine) Evaluate(req *domain.WafRequest) []*domain.SecurityEvent {
	var events []*domain.SecurityEvent
	sources := []string{req.Path, req.QueryArgs.Encode()}

	if len(req.Body) > 0 {
		if isJSON(req.Body) {
			jsonValues := middleware.ExtractValuesOnly(req.Body)
			sources = append(sources, jsonValues...)
		} else {
			sources = append(sources, string(req.Body))
		}
	}

	for _, source := range sources {
		if len(source) == 0 {
			continue
		}

		sourceUpper := strings.ToUpper(source)

		matches := e.matcher.Match([]byte(sourceUpper))

		for _, matchIdx := range matches {
			rule := e.rules[matchIdx]

			events = append(events, &domain.SecurityEvent{
				RuleID:      "AC-" + rule.Pattern,
				RuleName:    "Keyword: " + rule.Pattern,
				Severity:    rule.Severity,
				Message:     rule.Description,
				MatchedData: rule.Pattern,
			})
		}
	}

	return events
}

// Helper function to read the file
func loadRulesFromJSON(path string) ([]KeywordRule, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rules []KeywordRule
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&rules); err != nil {
		return nil, err
	}

	return rules, nil
}

func (e *FastMatchEngine) LoadRules() error {
	//@TODO: Hot reloading
	return nil
}

func isJSON(b []byte) bool {
	return len(b) > 0 && (b[0] == '{' || b[0] == '[')
}
