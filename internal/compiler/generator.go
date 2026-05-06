package compiler

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/samaasi/go-waf/internal/analysis/engines"
	"gopkg.in/yaml.v3"
)

// GenerateYAML converts parsed rules to CRSLangRule struct and writes them to the output directory.
func GenerateYAML(rules []ParsedRule, outputPath string) error {
	if err := os.MkdirAll(outputPath, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	for _, pr := range rules {
		if pr.ID == "" {
			continue // Skip rules without IDs (likely fragments)
		}

		crsRule := mapParsedToCRS(pr)

		filePath := filepath.Join(outputPath, fmt.Sprintf("rule-%s.yaml", pr.ID))
		data, err := yaml.Marshal(crsRule)
		if err != nil {
			return fmt.Errorf("failed to marshal rule %s: %w", pr.ID, err)
		}

		if err := os.WriteFile(filePath, data, 0644); err != nil {
			return fmt.Errorf("failed to write file %s: %w", filePath, err)
		}
	}

	return nil
}

func mapParsedToCRS(pr ParsedRule) engines.CRSLangRule {
	mappedVariable := pr.Variable
	if !strings.ContainsAny(pr.Variable, "|!&") && !strings.Contains(pr.Variable, ":") {
		switch pr.Variable {
		case "ARGS", "ARGS_GET", "ARGS_POST", "ARGS_NAMES":
			mappedVariable = "ARGS"
		case "REQUEST_HEADERS", "REQUEST_HEADERS_NAMES":
			mappedVariable = "REQUEST_HEADERS"
		case "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES":
			mappedVariable = "REQUEST_COOKIES"
		case "REQUEST_BODY":
			mappedVariable = "REQUEST_BODY"
		case "REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_FILENAME":
			mappedVariable = "REQUEST_URI"
		}
	}

	rule := engines.CRSLangRule{
		ID:               pr.ID,
		Msg:              pr.Msg,
		Severity:         pr.Severity,
		Phase:            pr.Phase,
		Action:           pr.Action,
		PreFilterKeyword: pr.PreFilterKeyword,
		Tags:             pr.Tags,
	}

	// Default severity for blocking rules if not specified
	if rule.Action == "block" && rule.Severity == 0 {
		rule.Severity = 10 // SeverityHigh
	}

	rule.Conditions = []struct {
		Operator        string   `yaml:"operator"`
		Variable        string   `yaml:"variable"`
		Value           string   `yaml:"value"`
		Transformations []string `yaml:"transformations"`
	}{
		{
			Operator:        pr.Operator,
			Variable:        mappedVariable,
			Value:           pr.Value,
			Transformations: pr.Transformations,
		},
	}

	for _, act := range pr.Actions {
		rule.Actions = append(rule.Actions, struct {
			Type  string `yaml:"type"`
			Key   string `yaml:"key"`
			Value string `yaml:"value"`
		}{
			Type:  act.Type,
			Key:   act.Key,
			Value: act.Value,
		})
	}

	for _, chained := range pr.Chain {
		crsChained := mapParsedToCRS(*chained)
		rule.Chain = append(rule.Chain, &crsChained)
	}

	return rule
}
