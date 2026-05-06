package engines

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"strings"

	"github.com/buger/jsonparser"
	"github.com/cloudflare/ahocorasick"
	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/pkg/utils"
	"gopkg.in/yaml.v3"
)

// CRSLangRule represents the modern YAML-based rule format.
type CRSLangRule struct {
	ID               string          `yaml:"id"`
	Msg              string          `yaml:"msg"`
	Severity         domain.Severity `yaml:"severity"`
	Phase            int             `yaml:"phase"`
	Action           string          `yaml:"action"`
	PreFilterKeyword string          `yaml:"pre_filter_keyword"`
	Conditions       []struct {
		Operator        string   `yaml:"operator"`
		Variable        string   `yaml:"variable"`
		Value           string   `yaml:"value"`
		Transformations []string `yaml:"transformations"`
	} `yaml:"conditions"`
	Actions []struct {
		Type  string `yaml:"type"` // setvar, expirevar, ctl
		Key   string `yaml:"key"`  // e.g. IP.event_count
		Value string `yaml:"value"`
	} `yaml:"actions"`
	Chain []*CRSLangRule `yaml:"chain"`
	Tags  []string       `yaml:"tags"`
}

// CRSLangEngine parses modern YAML-based OWASP CRS rules.
type CRSLangEngine struct {
	rulesPath string
	regexes   map[string]*regexp.Regexp
	rules     []CRSLangRule
	aho       *ahocorasick.Matcher
	keywords  []string
	store         domain.CollectionStore
	disabledRules map[string]bool
	mu            sync.RWMutex
}

func NewCRSLangEngine(rulesPath string, store domain.CollectionStore) *CRSLangEngine {
	return &CRSLangEngine{
		rulesPath:     rulesPath,
		regexes:       make(map[string]*regexp.Regexp),
		store:         store,
		disabledRules: make(map[string]bool),
	}
}

func (e *CRSLangEngine) ID() string   { return "crslang-yaml" }
func (e *CRSLangEngine) Name() string { return "CRSLang YAML Engine" }

func (e *CRSLangEngine) LoadRules() error {
	entries, err := os.ReadDir(e.rulesPath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		filePath := filepath.Join(e.rulesPath, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var rule CRSLangRule
		if err := yaml.Unmarshal(data, &rule); err != nil {
			continue
		}

		e.registerRuleRecursive(&rule)
		e.rules = append(e.rules, rule)
	}

	if len(e.keywords) > 0 {
		e.aho = ahocorasick.NewStringMatcher(e.keywords)
	}

	return nil
}

func (e *CRSLangEngine) registerRuleRecursive(rule *CRSLangRule) {
	for _, cond := range rule.Conditions {
		if cond.Operator == "@rx" || cond.Operator == "!@rx" {
			if _, ok := e.regexes[cond.Value]; !ok {
				re, err := regexp.Compile(cond.Value)
				if err == nil {
					e.regexes[cond.Value] = re
				}
			}
		}
	}

	if rule.PreFilterKeyword != "" {
		e.keywords = append(e.keywords, rule.PreFilterKeyword)
	}

	for _, chained := range rule.Chain {
		e.registerRuleRecursive(chained)
	}
}

func (e *CRSLangEngine) GetRules() []domain.RuleMetadata {
	e.mu.RLock()
	defer e.mu.RUnlock()

	res := make([]domain.RuleMetadata, len(e.rules))
	for i, r := range e.rules {
		res[i] = domain.RuleMetadata{
			ID:       r.ID,
			Name:     r.Msg,
			Severity: r.Severity,
			Enabled:  !e.disabledRules[r.ID],
			EngineID: e.ID(),
		}
	}
	return res
}

func (e *CRSLangEngine) ToggleRule(id string, enabled bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	found := false
	for _, r := range e.rules {
		if r.ID == id {
			found = true
			break
		}
	}
	if !found {
		return false
	}

	if enabled {
		delete(e.disabledRules, id)
	} else {
		e.disabledRules[id] = true
	}
	return true
}

func (e *CRSLangEngine) Evaluate(ctx context.Context, req *domain.WafRequest, phase int) []*domain.SecurityEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var events []*domain.SecurityEvent
	matchedKeywords := make(map[string]bool)
	if e.aho != nil && phase <= 2 {
		if len(req.Path) > 0 {
			for _, m := range e.aho.Match([]byte(req.Path)) {
				matchedKeywords[e.keywords[m]] = true
			}
		}
		if len(req.Body) > 0 {
			for _, m := range e.aho.Match(req.Body) {
				matchedKeywords[e.keywords[m]] = true
			}
		}
		for key, values := range req.QueryArgs {
			for _, m := range e.aho.Match([]byte(key)) {
				matchedKeywords[e.keywords[m]] = true
			}
			for _, val := range values {
				for _, m := range e.aho.Match([]byte(val)) {
					matchedKeywords[e.keywords[m]] = true
				}
			}
		}
	}

	for _, rule := range e.rules {
		if rule.Phase != phase {
			continue
		}
		if e.disabledRules[rule.ID] {
			continue
		}
		if req.DisabledRules != nil && req.DisabledRules[rule.ID] {
			continue
		}
		if rule.PreFilterKeyword != "" && !matchedKeywords[rule.PreFilterKeyword] {
			continue
		}

		matched, matchedVars := e.evaluateRule(ctx, &rule, req)
		if matched {
			// Apply Actions (setvar, etc)
			e.applyActions(ctx, &rule, req)

			event := &domain.SecurityEvent{
				RuleID:      rule.ID,
				RuleName:    rule.Msg,
				Severity:    rule.Severity,
				Message:     rule.Msg,
				MatchedData: "crslang_match",
				MatchedVars: matchedVars,
			}
			// Use the first matched value as the primary MatchedData for the main UI/Log
			for _, v := range matchedVars {
				event.MatchedData = v
				break
			}

			events = append(events, event)
		}
	}

	return events
}

func (e *CRSLangEngine) evaluateRule(ctx context.Context, rule *CRSLangRule, req *domain.WafRequest) (bool, map[string]string) {
	matchedVars := make(map[string]string)
	for _, cond := range rule.Conditions {
		searchSpace := e.extractVariable(ctx, req, cond.Variable)

		conditionMatched := false
		matchedData := ""

		for _, item := range searchSpace {
			transformed := item
			for _, t := range cond.Transformations {
				transformed = e.applyTransformation(transformed, t)
			}
			transformed = utils.NormalizeString(transformed)

			itemMatched := true
			itemData := ""

			switch cond.Operator {
			case "@rx":
				if re, ok := e.regexes[cond.Value]; ok {
					if !re.MatchString(transformed) {
						itemMatched = false
					} else {
						itemData = re.FindString(transformed)
					}
				}
			case "!@rx":
				if re, ok := e.regexes[cond.Value]; ok {
					if re.MatchString(transformed) {
						itemMatched = false
					}
				}
			case "@contains":
				if !utils.ContainsCaseInsensitive(transformed, cond.Value) {
					itemMatched = false
				} else {
					itemData = cond.Value
				}
			case "@pm":
				patterns := strings.Split(cond.Value, " ")
				found := false
				for _, p := range patterns {
					if p != "" && utils.ContainsCaseInsensitive(transformed, p) {
						found = true
						itemData = p
						break
					}
				}
				if !found {
					itemMatched = false
				}
			case "@gt":
				val, _ := strconv.Atoi(transformed)
				target, _ := strconv.Atoi(cond.Value)
				if val <= target {
					itemMatched = false
				} else {
					itemData = transformed
				}
			case "@lt":
				val, _ := strconv.Atoi(transformed)
				target, _ := strconv.Atoi(cond.Value)
				if val >= target {
					itemMatched = false
				} else {
					itemData = transformed
				}
			case "@beginsWith":
				if !strings.HasPrefix(transformed, cond.Value) {
					itemMatched = false
				} else {
					itemData = cond.Value
				}
			case "@endsWith":
				if !strings.HasSuffix(transformed, cond.Value) {
					itemMatched = false
				} else {
					itemData = cond.Value
				}
			case "@within":
				if !strings.Contains(cond.Value, transformed) {
					itemMatched = false
				} else {
					itemData = transformed
				}
			case "@streq":
				if transformed != cond.Value {
					itemMatched = false
				} else {
					itemData = cond.Value
				}
			case "@detectSQLi":
				if matched, fingerprint := utils.IsSQLi(transformed); matched {
					itemData = fingerprint
				} else {
					itemMatched = false
				}
			case "@detectXSS":
				if matched := utils.IsXSS(transformed); matched {
					itemData = "xss_detected"
				} else {
					itemMatched = false
				}
			}

			if itemMatched {
				conditionMatched = true
				matchedData = itemData
				break
			}
		}

		if !conditionMatched {
			return false, nil
		}
		matchedVars[cond.Variable] = matchedData
	}

	if len(rule.Chain) > 0 {
		for _, chainedRule := range rule.Chain {
			chainMatched, chainVars := e.evaluateRule(ctx, chainedRule, req)
			if !chainMatched {
				return false, nil
			}
			for k, v := range chainVars {
				matchedVars[k] = v
			}
		}
	}
	return true, matchedVars
}

func (e *CRSLangEngine) extractVariable(ctx context.Context, req *domain.WafRequest, variable string) []string {
	allVals := e.extractVariableMap(ctx, req, variable)
	var flat []string
	for _, vals := range allVals {
		flat = append(flat, vals...)
	}
	return flat
}

func (e *CRSLangEngine) extractVariableMap(ctx context.Context, req *domain.WafRequest, variable string) map[string][]string {
	result := make(map[string][]string)
	parts := strings.Split(variable, "|")
	
	for _, p := range parts {
		isCount := strings.HasPrefix(p, "&")
		if isCount {
			p = p[1:]
		}
		isNegated := strings.HasPrefix(p, "!")
		if isNegated {
			p = p[1:]
		}

		varName := p
		col := ""
		if strings.Contains(p, ":") {
			vParts := strings.SplitN(p, ":", 2)
			varName = vParts[0]
			col = vParts[1]
		}

		vals := e.extractSingleVariableMap(ctx, req, varName, col)
		
		if isNegated {
			for k := range vals {
				delete(result, k)
			}
			continue
		}

		if isCount {
			count := 0
			for _, v := range vals {
				count += len(v)
			}
			result["COUNT"] = []string{strconv.Itoa(count)}
		} else {
			for k, v := range vals {
				result[k] = append(result[k], v...)
			}
		}
	}
	return result
}

func (e *CRSLangEngine) extractSingleVariableMap(ctx context.Context, req *domain.WafRequest, variable string, col string) map[string][]string {
	col = strings.Trim(col, "/\"'")
	res := make(map[string][]string)

	if variable == "ARGS" && strings.HasPrefix(col, "grpc.") {
		// Example: ARGS:grpc.field.1
		if strings.HasPrefix(req.Headers.Get("Content-Type"), "application/grpc") {
			frames, _ := utils.ParseGrpcFrames(req.Body)
			for _, frame := range frames {
				fields := utils.ParseProtobuf(frame.Payload)
				if vals, ok := fields[col]; ok {
					res[col] = append(res[col], vals...)
				}
			}
			if len(res) > 0 {
				return res
			}
		}
		return nil
	}

	if variable == "ARGS" && strings.HasPrefix(col, "json.") {
		path := strings.TrimPrefix(col, "json.")
		keys := strings.Split(path, ".")
		val, _, _, err := jsonparser.Get(req.Body, keys...)
		if err == nil {
			res[col] = []string{string(val)}
			return res
		}
		return nil
	}

	if strings.Contains(variable, ".") {
		parts := strings.Split(variable, ".")
		if len(parts) == 2 && e.store != nil {
			colName := parts[0]
			key := parts[1]
			var id string
			switch colName {
			case "IP":
				id = req.RemoteIP
			case "SESSION":
				id = req.SessionID
			}
			if id != "" {
				val, _ := e.store.Get(ctx, colName, id, key)
				res[key] = []string{val}
				return res
			}
		}
	}

	switch variable {
	case "REQUEST_URI":
		res["REQUEST_URI"] = []string{req.Path}
	case "REQUEST_BODY":
		res["REQUEST_BODY"] = []string{string(req.Body)}
	case "ARGS", "ARGS_GET":
		for k, v := range req.QueryArgs {
			if col == "" || col == k {
				res[k] = v
			}
		}
	case "ARGS_NAMES":
		for k := range req.QueryArgs {
			if col == "" || col == k {
				res[k] = []string{k}
			}
		}
	case "REQUEST_HEADERS", "REQUEST_HEADERS_NAMES":
		for k, v := range req.Headers {
			if col == "" || strings.EqualFold(col, k) {
				if variable == "REQUEST_HEADERS" {
					res[k] = v
				} else {
					res[k] = []string{k}
				}
			}
		}
	case "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES":
		cookies := req.Headers["Cookie"]
		for _, c := range cookies {
			parts := strings.Split(c, ";")
			for _, part := range parts {
				p := strings.SplitN(strings.TrimSpace(part), "=", 2)
				k := p[0]
				if col == "" || col == k {
					if variable == "REQUEST_COOKIES" {
						if len(p) == 2 {
							res[k] = append(res[k], p[1])
						} else {
							res[k] = append(res[k], "")
						}
					} else {
						res[k] = append(res[k], k)
					}
				}
			}
		}
	case "TX":
		if col == "" {
			for k, v := range req.TX {
				res[k] = []string{fmt.Sprintf("%v", v)}
			}
		} else if val, ok := req.TX[col]; ok {
			res[col] = []string{fmt.Sprintf("%v", val)}
		}
	case "IP":
		if col != "" && e.store != nil {
			val, _ := e.store.Get(ctx, "IP", req.RemoteIP, col)
			if val != "" {
				res[col] = []string{val}
			}
		}
	case "SESSION":
		if col != "" && e.store != nil {
			val, _ := e.store.Get(ctx, "SESSION", req.SessionID, col)
			if val != "" {
				res[col] = []string{val}
			}
		}
	case "RESPONSE_STATUS":
		res["RESPONSE_STATUS"] = []string{strconv.Itoa(req.ResponseStatus)}
	case "RESPONSE_HEADERS", "RESPONSE_HEADERS_NAMES":
		for k, v := range req.ResponseHeaders {
			if col == "" || strings.EqualFold(col, k) {
				if variable == "RESPONSE_HEADERS" {
					res[k] = v
				} else {
					res[k] = []string{k}
				}
			}
		}
	case "REMOTE_ADDR":
		res["REMOTE_ADDR"] = []string{req.RemoteIP}
	case "REQUEST_METHOD":
		res["REQUEST_METHOD"] = []string{req.Method}
	}

	return res
}

func (e *CRSLangEngine) applyActions(ctx context.Context, rule *CRSLangRule, req *domain.WafRequest) {
	if e.store == nil {
		return
	}

	for _, action := range rule.Actions {
		switch action.Type {
		case "setvar":
			// Format: IP.event_count=1 or IP.event_count=+1 or TX.score=%{tx.score}
			parts := strings.Split(action.Key, ".")
			if len(parts) != 2 {
				continue
			}
			col := parts[0]
			key := parts[1]

			val := e.ExpandMacros(action.Value, req)

			if col == "TX" {
				if strings.HasPrefix(val, "+") {
					delta, _ := strconv.Atoi(val[1:])
					current, _ := req.TX[key].(int)
					req.TX[key] = current + delta
				} else if strings.HasPrefix(val, "-") {
					delta, _ := strconv.Atoi(val[1:])
					current, _ := req.TX[key].(int)
					req.TX[key] = current - delta
				} else {
					req.TX[key] = val
				}
				continue
			}

			var id string
			switch col {
			case "IP":
				id = req.RemoteIP
			case "SESSION":
				id = req.SessionID
			}

			if id == "" {
				continue
			}

			if strings.HasPrefix(val, "+") {
				delta, _ := strconv.Atoi(val[1:])
				e.store.Increment(ctx, col, id, key, delta, 24*time.Hour)
			} else if strings.HasPrefix(val, "-") {
				delta, _ := strconv.Atoi(val[1:])
				e.store.Increment(ctx, col, id, key, -delta, 24*time.Hour)
			} else {
				e.store.Set(ctx, col, id, key, val, 24*time.Hour)
			}
		case "ctl":
			if action.Key == "ruleRemoveById" {
				if req.DisabledRules == nil {
					req.DisabledRules = make(map[string]bool)
				}
				req.DisabledRules[action.Value] = true
			}
		}
	}
}

var macroRegex = regexp.MustCompile(`%\{([a-zA-Z0-9_\.:]+)\}`)

func (e *CRSLangEngine) ExpandMacros(input string, req *domain.WafRequest) string {
	return macroRegex.ReplaceAllStringFunc(input, func(m string) string {
		varName := strings.Trim(m, "%{}")
		vals := e.extractVariable(context.Background(), req, varName)
		if len(vals) > 0 {
			return vals[0]
		}
		return m
	})
}

func (e *CRSLangEngine) applyTransformation(input string, transformation string) string {
	switch transformation {
	case "t:lowercase":
		return strings.ToLower(input)
	case "t:removeWhitespace":
		return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(input, " ", ""), "\t", ""), "\n", "")
	case "t:urlDecode":
		decoded, err := url.QueryUnescape(input)
		if err == nil {
			return decoded
		}
		return input
	default:
		return input
	}
}
