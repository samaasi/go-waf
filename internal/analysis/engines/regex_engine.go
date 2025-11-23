package engines

import (
	"regexp"
	"strings"

	"go-waf/internal/domain"
)

// RegexRule implements domain.Rule
type RegexRule struct {
	id          string
	name        string
	pattern     *regexp.Regexp
	severity    domain.Severity
	targetField string
}

func (r *RegexRule) ID() string                { return r.id }
func (r *RegexRule) Name() string              { return r.name }
func (r *RegexRule) Tags() []string            { return []string{"regex"} }
func (r *RegexRule) Severity() domain.Severity { return r.severity }

func (r *RegexRule) Evaluate(req *domain.WafRequest) (bool, string) {
	var searchSpace string

	switch r.targetField {
	case "QUERY":
		searchSpace = req.QueryArgs.Encode()
	case "BODY":
		searchSpace = string(req.Body)
	case "HEADERS":
		var sb strings.Builder
		for k, v := range req.Headers {
			sb.WriteString(k)
			sb.WriteString(strings.Join(v, ""))
		}
		searchSpace = sb.String()
	default:
		searchSpace = req.Path
	}

	if r.pattern.MatchString(searchSpace) {
		return true, r.pattern.FindString(searchSpace)
	}
	return false, ""
}

// RegexEngine implements domain.RuleEngine
type RegexEngine struct {
	rules []RegexRule
}

func NewRegexEngine() *RegexEngine {
	// @TODO: load these from a YAML file or DB
	engine := &RegexEngine{
		rules: make([]RegexRule, 0),
	}

	engine.addRule("1001", "SQL Injection (UNION)", `(?i)\bunion\s+(all\s+)?select\b`, domain.SeverityCritical, "QUERY")
	engine.addRule("1002", "XSS (Script Tag)", `(?i)<script.*?>`, domain.SeverityHigh, "BODY")
	engine.addRule("1003", "Path Traversal", `\.\./\.\./`, domain.SeverityMedium, "PATH")

	return engine
}

func (re *RegexEngine) addRule(id, name, pattern string, sev domain.Severity, target string) {
	compiled, err := regexp.Compile(pattern)
	if err == nil {
		re.rules = append(re.rules, RegexRule{
			id:          id,
			name:        name,
			pattern:     compiled,
			severity:    sev,
			targetField: target,
		})
	}
}

func (re *RegexEngine) Evaluate(req *domain.WafRequest) []*domain.SecurityEvent {
	var events []*domain.SecurityEvent

	for _, rule := range re.rules {
		matched, matchData := rule.Evaluate(req)
		if matched {
			events = append(events, &domain.SecurityEvent{
				RuleID:      rule.ID(),
				RuleName:    rule.Name(),
				Severity:    rule.Severity(),
				Message:     "Pattern match detected",
				MatchedData: matchData,
			})
		}
	}
	return events
}

func (re *RegexEngine) LoadRules() error {
	// Placeholder for loading from file system
	return nil
}
