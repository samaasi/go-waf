package engines

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/pkg/utils"
)

// RegexRule implements domain.Rule
type RegexRule struct {
	id             string
	name           string
	pattern        *regexp.Regexp
	severity       domain.Severity
	targetField    string // PATH, QUERY, BODY, HEADERS, ANY
	targetSubField string // e.g., "User-Agent" for HEADERS
}

func (r *RegexRule) ID() string                { return r.id }
func (r *RegexRule) Name() string              { return r.name }
func (r *RegexRule) Tags() []string            { return []string{"regex"} }
func (r *RegexRule) Severity() domain.Severity { return r.severity }

// Evaluate is kept for domain.Rule interface compatibility, but the engine
// will primarily use matchNormalized for performance.
func (r *RegexRule) Evaluate(req *domain.WafRequest) (bool, string) {
	var searchSpace string
	switch r.targetField {
	case "QUERY":
		searchSpace = req.QueryArgs.Encode()
	case "BODY":
		searchSpace = string(req.Body)
	case "HEADERS":
		if r.targetSubField != "" {
			searchSpace = req.Headers.Get(r.targetSubField)
		} else {
			var sb strings.Builder
			for k, v := range req.Headers {
				sb.WriteString(k)
				sb.WriteString(":")
				sb.WriteString(strings.Join(v, ","))
				sb.WriteString(" ")
			}
			searchSpace = sb.String()
		}
	default:
		searchSpace = req.Path
	}

	normalized := utils.NormalizeString(searchSpace)
	return r.matchNormalized(normalized)
}

func (r *RegexRule) matchNormalized(normalized string) (bool, string) {
	if r.pattern.MatchString(normalized) {
		return true, r.pattern.FindString(normalized)
	}
	return false, ""
}

// RegexEngine implements domain.RuleEngine
type RegexEngine struct {
	pathRules   []*RegexRule
	queryRules  []*RegexRule
	bodyRules   []*RegexRule
	headerRules map[string][]*RegexRule // map[headerName]rules
	anyRules    []*RegexRule
	rulePath    string
}

func NewRegexEngine() *RegexEngine {
	return &RegexEngine{
		headerRules: make(map[string][]*RegexRule),
	}
}

func NewRegexEngineWithPath(path string) *RegexEngine {
	return &RegexEngine{
		headerRules: make(map[string][]*RegexRule),
		rulePath:    path,
	}
}

func (re *RegexEngine) Evaluate(req *domain.WafRequest) []*domain.SecurityEvent {
	var events []*domain.SecurityEvent

	// 1. Evaluate Path rules
	if len(re.pathRules) > 0 {
		normPath := utils.NormalizeString(req.Path)
		for _, r := range re.pathRules {
			if matched, data := r.matchNormalized(normPath); matched {
				events = append(events, re.createEvent(r, data))
			}
		}
	}

	// 2. Evaluate Query rules
	if len(re.queryRules) > 0 {
		normQuery := utils.NormalizeString(req.QueryArgs.Encode())
		for _, r := range re.queryRules {
			if matched, data := r.matchNormalized(normQuery); matched {
				events = append(events, re.createEvent(r, data))
			}
		}
	}

	// 3. Evaluate Body rules
	if len(re.bodyRules) > 0 {
		normBody := utils.NormalizeString(string(req.Body))
		for _, r := range re.bodyRules {
			if matched, data := r.matchNormalized(normBody); matched {
				events = append(events, re.createEvent(r, data))
			}
		}
	}

	// 4. Evaluate Header rules
	for hName, rules := range re.headerRules {
		hVal := req.Headers.Get(hName)
		if hVal == "" {
			continue
		}
		normHVal := utils.NormalizeString(hVal)
		for _, r := range rules {
			if matched, data := r.matchNormalized(normHVal); matched {
				events = append(events, re.createEvent(r, data))
			}
		}
	}

	// 5. Any rules (last resort, evaluate against everything)
	if len(re.anyRules) > 0 {
		// This is slow, ideally we don't have many 'ANY' rules
		normAll := utils.NormalizeString(fmt.Sprintf("%s %s %s", req.Path, req.QueryArgs.Encode(), string(req.Body)))
		for _, r := range re.anyRules {
			if matched, data := r.matchNormalized(normAll); matched {
				events = append(events, re.createEvent(r, data))
			}
		}
	}

	return events
}

func (re *RegexEngine) createEvent(r *RegexRule, matchData string) *domain.SecurityEvent {
	return &domain.SecurityEvent{
		RuleID:      r.ID(),
		RuleName:    r.Name(),
		Severity:    r.Severity(),
		Message:     "Pattern match detected",
		MatchedData: matchData,
	}
}

type regexRuleJSON struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Pattern     string          `json:"pattern"`
	Severity    domain.Severity `json:"severity"`
	TargetField string          `json:"target"` // Can be "HEADERS:User-Agent"
}

func (re *RegexEngine) LoadRules() error {
	if re.rulePath == "" {
		return nil
	}
	f, err := os.Open(re.rulePath)
	if err != nil {
		return err
	}
	defer f.Close()

	var items []regexRuleJSON
	if err := json.NewDecoder(f).Decode(&items); err != nil {
		return err
	}

	// Reset rules
	re.pathRules = nil
	re.queryRules = nil
	re.bodyRules = nil
	re.headerRules = make(map[string][]*RegexRule)
	re.anyRules = nil

	for _, it := range items {
		compiled, err := regexp.Compile(it.Pattern)
		if err != nil {
			continue
		}

		target := it.TargetField
		subField := ""
		if strings.Contains(target, ":") {
			parts := strings.SplitN(target, ":", 2)
			target = parts[0]
			subField = parts[1]
		}

		rule := &RegexRule{
			id:             it.ID,
			name:           it.Name,
			pattern:        compiled,
			severity:       it.Severity,
			targetField:    target,
			targetSubField: subField,
		}

		switch target {
		case "PATH":
			re.pathRules = append(re.pathRules, rule)
		case "QUERY":
			re.queryRules = append(re.queryRules, rule)
		case "BODY":
			re.bodyRules = append(re.bodyRules, rule)
		case "HEADERS":
			if subField != "" {
				re.headerRules[subField] = append(re.headerRules[subField], rule)
			} else {
				// If no subfield, treat as generic header rule (maybe add to anyRules or handle separately)
				re.anyRules = append(re.anyRules, rule)
			}
		default:
			re.pathRules = append(re.pathRules, rule) // Default to Path
		}
	}
	return nil
}
