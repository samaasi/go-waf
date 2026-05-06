package engines

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/pkg/utils"

	"github.com/cloudflare/ahocorasick"
)

var builderPool = sync.Pool{
	New: func() interface{} {
		return &strings.Builder{}
	},
}

// FastMatchEngine handles massive keyword lists using the Aho-Corasick algorithm.
type FastMatchEngine struct {
	matcher  *ahocorasick.Matcher
	rules    []KeywordRule
	rulePath string
	mu       sync.RWMutex
}

// KeywordRule now includes JSON tags for loading
type KeywordRule struct {
	Pattern     string          `json:"pattern"`
	Severity    domain.Severity `json:"severity"`
	Description string          `json:"description"`
}

// NewFastMatchEngine loads rules from a file and builds the Aho-Corasick matcher.
func NewFastMatchEngine(rulePath string) (*FastMatchEngine, error) {
	e := &FastMatchEngine{
		rulePath: rulePath,
	}

	if err := e.LoadRules(); err != nil {
		return nil, err
	}

	return e, nil
}

func (e *FastMatchEngine) ID() string                { return "fast-match" }
func (e *FastMatchEngine) Name() string              { return "Aho-Corasick Scanner" }
func (e *FastMatchEngine) Tags() []string            { return []string{"fast", "pre-filter", "dfa"} }
func (e *FastMatchEngine) Severity() domain.Severity { return domain.SeverityMedium }

func (e *FastMatchEngine) GetRules() []domain.RuleMetadata {
	e.mu.RLock()
	defer e.mu.RUnlock()
	res := make([]domain.RuleMetadata, len(e.rules))
	for i, r := range e.rules {
		res[i] = domain.RuleMetadata{
			ID:       "AC-" + r.Pattern,
			Name:     r.Description,
			Severity: r.Severity,
			Enabled:  true,
			EngineID: e.ID(),
		}
	}
	return res
}

func (e *FastMatchEngine) ToggleRule(id string, enabled bool) bool {
	return false
}

func (e *FastMatchEngine) Evaluate(ctx context.Context, req *domain.WafRequest, phase int) []*domain.SecurityEvent {
	e.mu.RLock()
	matcher := e.matcher
	rules := e.rules
	e.mu.RUnlock()

	if matcher == nil {
		return nil
	}

	var events []*domain.SecurityEvent
	sb := builderPool.Get().(*strings.Builder)
	sb.Reset()
	defer builderPool.Put(sb)

	// Build a single search space for efficient one-pass Aho-Corasick matching
	// Path + Query
	sb.WriteString(req.Path)
	sb.WriteString(" ")
	sb.WriteString(req.QueryArgs.Encode())
	sb.WriteString(" ")

	// Headers
	for k, v := range req.Headers {
		sb.WriteString(k)
		sb.WriteString(":")
		sb.WriteString(strings.Join(v, ","))
		sb.WriteString(" ")
	}

	// Body
	if len(req.Body) > 0 {
		if isJSON(req.Body) {
			jsonValues := utils.ExtractValuesOnly(req.Body)
			for _, v := range jsonValues {
				sb.WriteString(v)
				sb.WriteString(" ")
			}
		} else {
			sb.Write(req.Body)
		}
	}

	fullSearchSpace := sb.String()
	if len(fullSearchSpace) == 0 {
		return nil
	}

	normalized := utils.NormalizeString(fullSearchSpace)
	upper := strings.ToUpper(normalized)

	matches := matcher.Match([]byte(upper))

	// Dedup events by rule ID to avoid spamming multiple matches of the same rule in the same request
	seen := make(map[string]bool)

	for _, matchIdx := range matches {
		rule := rules[matchIdx]
		if seen[rule.Pattern] {
			continue
		}
		seen[rule.Pattern] = true

		events = append(events, &domain.SecurityEvent{
			RuleID:      "AC-" + rule.Pattern,
			RuleName:    "Keyword: " + rule.Pattern,
			Severity:    rule.Severity,
			Message:     rule.Description,
			MatchedData: rule.Pattern,
		})
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
	rules, err := loadRulesFromJSON(e.rulePath)
	if err != nil {
		return fmt.Errorf("failed to load fast-match rules: %w", err)
	}

	if len(rules) == 0 {
		return fmt.Errorf("no rules found in %s", e.rulePath)
	}

	patterns := make([]string, len(rules))
	for i := range rules {
		rules[i].Pattern = strings.ToUpper(rules[i].Pattern)
		patterns[i] = rules[i].Pattern
	}

	matcher := ahocorasick.NewStringMatcher(patterns)

	e.mu.Lock()
	e.rules = rules
	e.matcher = matcher
	e.mu.Unlock()

	return nil
}

func isJSON(b []byte) bool {
	return len(b) > 0 && (b[0] == '{' || b[0] == '[')
}
