package engines

import (
    "encoding/json"
    "os"
    "regexp"
    "strings"

    "go-waf/internal/domain"
    "go-waf/pkg/utils"
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

    normalized := utils.NormalizeString(searchSpace)
    if r.pattern.MatchString(normalized) {
        return true, r.pattern.FindString(normalized)
    }
    return false, ""
}

// RegexEngine implements domain.RuleEngine
type RegexEngine struct {
    rules []RegexRule
    rulePath string
}

func NewRegexEngine() *RegexEngine {
    engine := &RegexEngine{
        rules: make([]RegexRule, 0),
    }
    return engine
}

func NewRegexEngineWithPath(path string) *RegexEngine {
    engine := &RegexEngine{
        rules: make([]RegexRule, 0),
        rulePath: path,
    }
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

type regexRuleJSON struct {
    ID          string            `json:"id"`
    Name        string            `json:"name"`
    Pattern     string            `json:"pattern"`
    Severity    domain.Severity   `json:"severity"`
    TargetField string            `json:"target"`
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
    dec := json.NewDecoder(f)
    if err := dec.Decode(&items); err != nil {
        return err
    }
    re.rules = make([]RegexRule, 0, len(items))
    for _, it := range items {
        compiled, err := regexp.Compile(it.Pattern)
        if err != nil {
            continue
        }
        re.rules = append(re.rules, RegexRule{
            id:          it.ID,
            name:        it.Name,
            pattern:     compiled,
            severity:    it.Severity,
            targetField: it.TargetField,
        })
    }
    return nil
}
