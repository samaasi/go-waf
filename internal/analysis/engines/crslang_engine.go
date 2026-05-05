package engines

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/pkg/utils"
	"gopkg.in/yaml.v3"
)

// CRSLangRule represents the modern YAML-based rule format.
type CRSLangRule struct {
	ID         string          `yaml:"id"`
	Msg        string          `yaml:"msg"`
	Severity   domain.Severity `yaml:"severity"`
	Conditions []struct {
		Operator string `yaml:"operator"`
		Variable string `yaml:"variable"`
		Value    string `yaml:"value"`
	} `yaml:"conditions"`
	Tags []string `yaml:"tags"`
}

// CRSLangEngine parses modern YAML-based OWASP CRS rules.
type CRSLangEngine struct {
	rulesPath string
	regexes   map[string]*regexp.Regexp
	rules     []CRSLangRule
}

func NewCRSLangEngine(rulesPath string) *CRSLangEngine {
	return &CRSLangEngine{
		rulesPath: rulesPath,
		regexes:   make(map[string]*regexp.Regexp),
	}
}

func (e *CRSLangEngine) ID() string   { return "crslang-yaml" }
func (e *CRSLangEngine) Name() string { return "CRSLang YAML Engine" }

func (e *CRSLangEngine) LoadRules() error {
	files, err := filepath.Glob(filepath.Join(e.rulesPath, "*.yaml"))
	if err != nil {
		return err
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var rule CRSLangRule
		if err := yaml.Unmarshal(data, &rule); err != nil {
			continue
		}

		// Compile regexes for conditions
		for _, cond := range rule.Conditions {
			if cond.Operator == "@rx" || cond.Operator == "!@rx" {
				re, err := regexp.Compile(cond.Value)
				if err != nil {
					return fmt.Errorf("invalid regex in rule %s: %w", rule.ID, err)
				}
				e.regexes[cond.Value] = re
			}
		}
		e.rules = append(e.rules, rule)
	}

	return nil
}

func (e *CRSLangEngine) Evaluate(req *domain.WafRequest) []*domain.SecurityEvent {
	var events []*domain.SecurityEvent

	for _, rule := range e.rules {
		matched := true
		for _, cond := range rule.Conditions {
			// Extract search space based on variable
			searchSpace := e.extractVariable(req, cond.Variable)
			searchSpace = utils.NormalizeString(searchSpace)

			// Evaluate operator
			switch cond.Operator {
			case "@rx":
				if re, ok := e.regexes[cond.Value]; ok {
					if !re.MatchString(searchSpace) {
						matched = false
					}
				}
			case "!@rx":
				if re, ok := e.regexes[cond.Value]; ok {
					if re.MatchString(searchSpace) {
						matched = false
					}
				}
			case "@contains":
				if !utils.ContainsCaseInsensitive(searchSpace, cond.Value) {
					matched = false
				}
			}

			if !matched {
				break
			}
		}

		if matched {
			events = append(events, &domain.SecurityEvent{
				RuleID:      rule.ID,
				RuleName:    rule.Msg,
				Severity:    rule.Severity,
				Message:     rule.Msg,
				MatchedData: "crslang_match",
			})
		}
	}

	return events
}

func (e *CRSLangEngine) extractVariable(req *domain.WafRequest, variable string) string {
	switch variable {
	case "REQUEST_URI":
		return req.Path
	case "REQUEST_BODY":
		return string(req.Body)
	case "ARGS_GET":
		return req.QueryArgs.Encode()
	default:
		return req.Path
	}
}
