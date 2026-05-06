package compiler

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp/syntax"
	"strconv"
	"strings"

	"github.com/samaasi/go-waf/internal/domain"
)

// ParsedRule represents the intermediate state of a rule
type ParsedRule struct {
	ID               string
	Phase            int
	Action           string
	Msg              string
	Severity         domain.Severity
	Variable         string
	Operator         string
	Value            string
	Transformations  []string
	Tags             []string
	PreFilterKeyword string
	IsChain          bool
	Chain            []*ParsedRule
	Actions          []ParsedAction
}

type ParsedAction struct {
	Type  string
	Key   string
	Value string
}

type Compiler struct {
	logger domain.Logger
}

func NewCompiler(logger domain.Logger) *Compiler {
	return &Compiler{logger: logger}
}

// ParseFile parses a ModSecurity SecLang file and returns a list of ParsedRules.
func (c *Compiler) ParseFile(path string) ([]ParsedRule, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rules []ParsedRule
	var currentRuleBuilder strings.Builder
	var rootRule *ParsedRule

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle continuation lines
		isContinuation := strings.HasSuffix(line, "\\")
		if isContinuation {
			currentRuleBuilder.WriteString(strings.TrimSuffix(line, "\\"))
			currentRuleBuilder.WriteString(" ")
			continue
		}

		currentRuleBuilder.WriteString(line)
		fullDirective := currentRuleBuilder.String()
		currentRuleBuilder.Reset()

		if strings.HasPrefix(fullDirective, "SecRule ") || strings.HasPrefix(fullDirective, "SecAction ") {
			var parsed *ParsedRule
			var err error

			if strings.HasPrefix(fullDirective, "SecAction ") {
				// Map SecAction to a dummy SecRule that always matches
				// Actions in SecAction are the same as SecRule actions
				actionContent := strings.TrimPrefix(fullDirective, "SecAction ")
				dummyRule := fmt.Sprintf("SecRule TX:dummy \"@rx .*\" %s", actionContent)
				parsed, err = c.ParseRule(dummyRule, path)
			} else {
				parsed, err = c.ParseRule(fullDirective, path)
			}

			if err != nil {
				c.logger.Warn("Failed to parse rule", domain.String("rule", fullDirective), domain.Any("error", err))
				rootRule = nil
				continue
			}

			if rootRule != nil {
				// We are in a chain
				rootRule.Chain = append(rootRule.Chain, parsed)
				if !parsed.IsChain {
					// End of chain
					rootRule = nil
				}
			} else {
				// New root rule
				rules = append(rules, *parsed)
				if parsed.IsChain {
					rootRule = &rules[len(rules)-1]
				}
			}
		} else if strings.HasPrefix(fullDirective, "SecMarker ") {
			// Markers are used for skipAfter target
			marker := strings.TrimPrefix(fullDirective, "SecMarker ")
			marker = strings.Trim(marker, "\" ")
			// For now, we don't store markers in YAML, but we could add them if needed for skipAfter logic
		} else {
			// Not a SecRule (e.g. SecAction, SecMarker), reset chain state
			rootRule = nil
		}
	}

	return rules, scanner.Err()
}

// ParseRule parses a single SecRule directive robustly.
// Expected format: SecRule VARIABLES "OPERATOR" "ACTIONS"
func (c *Compiler) ParseRule(directive string, path string) (*ParsedRule, error) {
	// A robust tokenizer handling quotes and escape sequences
	parts := parseTokens(directive)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid SecRule format")
	}

	variable := parts[1]
	operatorToken := parts[2]
	actionsToken := ""
	if len(parts) > 3 {
		actionsToken = parts[3]
	}

	// Clean operator token
	operatorToken = strings.Trim(operatorToken, "\"")
	operator := "@rx" // default if not specified
	value := operatorToken

	if strings.HasPrefix(operatorToken, "@") {
		opParts := strings.SplitN(operatorToken, " ", 2)
		operator = opParts[0]
		if len(opParts) > 1 {
			value = opParts[1]
		} else {
			value = ""
		}
	} else if strings.HasPrefix(operatorToken, "!@") {
		opParts := strings.SplitN(operatorToken, " ", 2)
		operator = opParts[0]
		if len(opParts) > 1 {
			value = opParts[1]
		} else {
			value = ""
		}
	} else if strings.HasPrefix(operatorToken, "@") || strings.HasPrefix(operatorToken, "!@") {
		// General operator handling
		if strings.HasPrefix(operatorToken, "!@") {
			// handled below via opParts
		}
		opParts := strings.SplitN(operatorToken, " ", 2)
		operator = opParts[0]
		if len(opParts) > 1 {
			value = opParts[1]
		} else {
			value = ""
		}
	}

	if operator == "@pmFromFile" {
		dataFile := value
		if !filepath.IsAbs(dataFile) {
			dataFile = filepath.Join(filepath.Dir(path), dataFile)
		}
		data, err := os.ReadFile(dataFile)
		if err != nil {
			c.logger.Warn("Failed to read @pmFromFile", domain.String("file", dataFile), domain.Any("error", err))
		} else {
			operator = "@pm"
			var patterns []string
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				patterns = append(patterns, line)
			}
			value = strings.Join(patterns, " ")
		}
	}

	rule := &ParsedRule{
		Variable: variable,
		Operator: operator,
		Value:    value,
		Severity: 0,
		Action:   "block",
		Phase:    2,
	}

	// Parse actions
	actions := strings.Split(strings.Trim(actionsToken, "\""), ",")
	for _, action := range actions {
		action = strings.TrimSpace(action)
		parts := strings.SplitN(action, ":", 2)
		key := parts[0]
		val := ""
		if len(parts) > 1 {
			val = strings.Trim(parts[1], "'\"")
		}

		switch key {
		case "id":
			rule.ID = val
		case "msg":
			rule.Msg = val
		case "phase":
			if p, err := strconv.Atoi(val); err == nil {
				rule.Phase = p
			}
		case "t":
			rule.Transformations = append(rule.Transformations, "t:"+val)
		case "tag":
			rule.Tags = append(rule.Tags, val)
		case "severity":
			switch strings.ToLower(val) {
			case "critical":
				rule.Severity = domain.SeverityCritical
			case "high":
				rule.Severity = domain.SeverityHigh
			case "medium":
				rule.Severity = domain.SeverityMedium
			case "low":
				rule.Severity = domain.SeverityLow
			default:
				if s, err := strconv.Atoi(val); err == nil {
					rule.Severity = domain.Severity(s)
				}
			}
		case "pass":
			rule.Action = "allow"
			rule.Severity = 0 // pass rules shouldn't contribute to score
		case "deny", "drop", "block":
			rule.Action = "block"
		case "chain":
			rule.IsChain = true
		case "log":
			// Handled inherently by WAF if it matches
		}

		if strings.HasPrefix(action, "setvar:") {
			val := strings.TrimPrefix(action, "setvar:")
			parts := strings.SplitN(val, "=", 2)
			if len(parts) == 2 {
				rule.Actions = append(rule.Actions, ParsedAction{
					Type:  "setvar",
					Key:   strings.Trim(parts[0], "'\" "),
					Value: strings.Trim(parts[1], "'\" "),
				})
			}
		}

		if strings.HasPrefix(action, "expirevar:") {
			val := strings.TrimPrefix(action, "expirevar:")
			parts := strings.SplitN(val, "=", 2)
			if len(parts) == 2 {
				rule.Actions = append(rule.Actions, ParsedAction{
					Type:  "expirevar",
					Key:   strings.Trim(parts[0], "'\" "),
					Value: strings.Trim(parts[1], "'\" "),
				})
			}
		}

		if strings.HasPrefix(action, "ctl:") {
			val := strings.TrimPrefix(action, "ctl:")
			parts := strings.SplitN(val, "=", 2)
			if len(parts) == 2 {
				rule.Actions = append(rule.Actions, ParsedAction{
					Type:  "ctl",
					Key:   strings.Trim(parts[0], "'\" "),
					Value: strings.Trim(parts[1], "'\" "),
				})
			}
		}
	}

	// Support @pmFromFile by reading the file
	if rule.Operator == "@pmFromFile" {
		dataFilePath := filepath.Join(filepath.Dir(path), rule.Value)
		data, err := os.ReadFile(dataFilePath)
		if err == nil {
			patterns := strings.Split(string(data), "\n")
			var filtered []string
			for _, p := range patterns {
				p = strings.TrimSpace(p)
				if p != "" && !strings.HasPrefix(p, "#") {
					filtered = append(filtered, p)
				}
			}
			rule.Value = strings.Join(filtered, " ")
			rule.Operator = "@pm"
		} else {
			c.logger.Warn("Failed to load @pmFromFile", domain.String("path", dataFilePath), domain.Any("error", err))
		}
	}

	// Extract keyword for Aho-Corasick
	rule.PreFilterKeyword = c.ExtractPreFilterKeyword(rule.Operator, rule.Value)

	return rule, nil
}

// ExtractPreFilterKeyword attempts to find the longest static string inside a regex pattern.
// It uses an Abstract Syntax Tree (AST) to robustly extract literal sequences.
func (c *Compiler) ExtractPreFilterKeyword(operator, value string) string {
	if operator == "@contains" || operator == "@streq" {
		return value
	}
	if operator == "@pm" {
		parts := strings.Split(value, " ")
		longest := ""
		for _, p := range parts {
			if len(p) > len(longest) {
				longest = p
			}
		}
		return longest
	}

	if operator == "@rx" || operator == "!@rx" {
		reAST, err := syntax.Parse(value, syntax.Perl)
		if err != nil {
			return ""
		}

		longest := ""
		var walk func(node *syntax.Regexp)
		walk = func(node *syntax.Regexp) {
			if node.Op == syntax.OpLiteral {
				str := string(node.Rune)
				if len(str) > len(longest) {
					longest = str
				}
			}
			for _, sub := range node.Sub {
				walk(sub)
			}
		}
		walk(reAST)

		return strings.ToLower(longest)
	}

	return ""
}

// parseTokens implements a robust scanner to tokenize SecLang directives, handling escapes and quotes.
func parseTokens(line string) []string {
	var tokens []string
	var current strings.Builder
	var inQuotes, inSingleQuotes, escapeNext bool

	for i := 0; i < len(line); i++ {
		char := line[i]

		if escapeNext {
			current.WriteByte(char)
			escapeNext = false
			continue
		}

		if char == '\\' {
			escapeNext = true
			continue
		}

		if char == '"' && !inSingleQuotes {
			inQuotes = !inQuotes
			current.WriteByte(char)
			continue
		}

		if char == '\'' && !inQuotes {
			inSingleQuotes = !inSingleQuotes
			current.WriteByte(char)
			continue
		}

		if char == ' ' && !inQuotes && !inSingleQuotes {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			continue
		}

		current.WriteByte(char)
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}
