package engines

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/pkg/utils"

	"github.com/cloudflare/ahocorasick"
)

type DlpRule struct {
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
}

// DlpEngine specializes in detecting sensitive data in outbound responses.
type DlpEngine struct {
	matcher *ahocorasick.Matcher
	rules   []DlpRule
}

func NewDlpEngine(rulePath string) (*DlpEngine, error) {
	rules, err := loadDlpRules(rulePath)
	if err != nil {
		return nil, err
	}

	patterns := make([]string, len(rules))
	for i, r := range rules {
		patterns[i] = strings.ToUpper(r.Pattern)
	}

	return &DlpEngine{
		matcher: ahocorasick.NewStringMatcher(patterns),
		rules:   rules,
	}, nil
}

func loadDlpRules(path string) ([]DlpRule, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open DLP rules: %w", err)
	}
	defer file.Close()

	var rules []DlpRule
	if err := json.NewDecoder(file).Decode(&rules); err != nil {
		return nil, fmt.Errorf("failed to decode DLP rules: %w", err)
	}
	return rules, nil
}

func (e *DlpEngine) ID() string { return "dlp-scanner" }

func (e *DlpEngine) InspectResponse(body []byte) []*domain.SecurityEvent {
	if len(body) == 0 {
		return nil
	}

	// Light normalization for response bodies
	normBody := utils.NormalizeString(string(body))
	upperBody := strings.ToUpper(normBody)

	matches := e.matcher.Match([]byte(upperBody))
	if len(matches) == 0 {
		return nil
	}

	var events []*domain.SecurityEvent
	for _, matchIdx := range matches {
		rule := e.rules[matchIdx]
		events = append(events, &domain.SecurityEvent{
			RuleID:      "DLP-" + rule.Pattern,
			RuleName:    "Sensitive Data Exposure",
			Severity:    domain.SeverityCritical,
			Message:     "Found sensitive pattern in response: " + rule.Description,
			MatchedData: rule.Pattern,
		})
	}

	return events
}
