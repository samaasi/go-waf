package engines

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/samaasi/go-waf/internal/domain"

	"github.com/cloudflare/ahocorasick"
)

type DlpRule struct {
	ID          string `json:"id"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	IsRegex     bool   `json:"is_regex"`
}

var builtInRules = []DlpRule{
	{ID: "DLP-PAN", Pattern: `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b`, Description: "Credit Card Number (PAN)", IsRegex: true},
	{ID: "DLP-SSN", Pattern: `\b\d{3}-\d{2}-\d{4}\b`, Description: "Social Security Number (SSN)", IsRegex: true},
	{ID: "DLP-KEY", Pattern: `(?i)(?:api_key|secret_key|access_token|private_key)["']?\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{16,})`, Description: "API Key or Secret", IsRegex: true},
	{ID: "DLP-EMAIL", Pattern: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, Description: "Email Address", IsRegex: true},
	{ID: "DLP-PHONE", Pattern: `\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`, Description: "Phone Number", IsRegex: true},
}

// DlpEngine specializes in detecting sensitive data in outbound responses.
type DlpEngine struct {
	matcher     *ahocorasick.Matcher
	staticRules []DlpRule
	regexRules  []struct {
		DlpRule
		re *regexp.Regexp
	}
}

func NewDlpEngine(rulePath string) (*DlpEngine, error) {
	e := &DlpEngine{}

	// Load custom rules if path exists
	if rulePath != "" {
		if _, err := os.Stat(rulePath); err == nil {
			customRules, err := loadDlpRules(rulePath)
			if err != nil {
				return nil, err
			}
			for _, r := range customRules {
				if r.IsRegex {
					re, err := regexp.Compile(r.Pattern)
					if err != nil {
						return nil, fmt.Errorf("invalid DLP regex %s: %w", r.ID, err)
					}
					e.regexRules = append(e.regexRules, struct {
						DlpRule
						re *regexp.Regexp
					}{r, re})
				} else {
					e.staticRules = append(e.staticRules, r)
				}
			}
		}
	}

	// Add built-in rules
	for _, r := range builtInRules {
		re := regexp.MustCompile(r.Pattern)
		e.regexRules = append(e.regexRules, struct {
			DlpRule
			re *regexp.Regexp
		}{r, re})
	}

	if len(e.staticRules) > 0 {
		patterns := make([]string, len(e.staticRules))
		for i, r := range e.staticRules {
			patterns[i] = strings.ToUpper(r.Pattern)
		}
		e.matcher = ahocorasick.NewStringMatcher(patterns)
	}

	return e, nil
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

func (e *DlpEngine) InspectResponse(body []byte) []*domain.SecurityEvent {
	if len(body) == 0 {
		return nil
	}

	var events []*domain.SecurityEvent
	bodyStr := string(body)

	// 1. Keyword Matching
	if e.matcher != nil {
		upperBody := strings.ToUpper(bodyStr)
		matches := e.matcher.Match([]byte(upperBody))
		for _, matchIdx := range matches {
			rule := e.staticRules[matchIdx]
			events = append(events, &domain.SecurityEvent{
				RuleID:      rule.ID,
				RuleName:    "Sensitive Keyword Exposure",
				Severity:    domain.SeverityHigh,
				Message:     "Found sensitive keyword: " + rule.Description,
				MatchedData: rule.Pattern,
			})
		}
	}

	// 2. Regex Matching
	for _, r := range e.regexRules {
		if r.re.Match(body) {
			match := r.re.FindString(bodyStr)
			events = append(events, &domain.SecurityEvent{
				RuleID:      r.ID,
				RuleName:    "Sensitive Pattern Exposure",
				Severity:    domain.SeverityCritical,
				Message:     "Found sensitive pattern: " + r.Description,
				MatchedData: maskString(match), // Anonymize for telemetry
			})
		}
	}

	return events
}

// Mask replaces sensitive data in the body with asterisks.
func (e *DlpEngine) Mask(body []byte) []byte {
	result := body
	for _, r := range e.regexRules {
		result = r.re.ReplaceAllFunc(result, func(match []byte) []byte {
			return []byte(maskString(string(match)))
		})
	}
	// Note: Static keywords are usually not masked to avoid breaking legitimate content, 
	// but could be added here if needed.
	return result
}

func maskString(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}
