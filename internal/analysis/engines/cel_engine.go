package engines

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/cel-go/cel"
	"github.com/samaasi/go-waf/internal/domain"
)

type CelRule struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Expression string          `json:"expression"`
	Severity   domain.Severity `json:"severity"`
	Program    cel.Program     `json:"-"`
}

type CelEngine struct {
	env      *cel.Env
	rules    []CelRule
	rulePath string
	logger   domain.Logger
}

func NewCelEngine(rulePath string, log domain.Logger) (*CelEngine, error) {
	env, err := cel.NewEnv(
		cel.Variable("method", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("remote_ip", cel.StringType),
		cel.Variable("body", cel.StringType),
		cel.Variable("headers", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
		cel.Variable("query", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL env: %w", err)
	}

	return &CelEngine{
		env:      env,
		rulePath: rulePath,
		logger:   log,
	}, nil
}

func (e *CelEngine) ID() string   { return "cel-programmable" }
func (e *CelEngine) Name() string { return "CEL Programmable Engine" }

func (e *CelEngine) Evaluate(req *domain.WafRequest) []*domain.SecurityEvent {
	if len(e.rules) == 0 {
		return nil
	}

	// Prepare data for CEL execution (Zero-allocation maps where possible)
	data := map[string]interface{}{
		"method":    req.Method,
		"path":      req.Path,
		"remote_ip": req.RemoteIP,
		"body":      string(req.Body),
		"headers":   map[string][]string(req.Headers),
		"query":     map[string][]string(req.QueryArgs),
	}

	var events []*domain.SecurityEvent
	for _, rule := range e.rules {
		out, _, err := rule.Program.Eval(data)
		if err != nil {
			e.logger.Debug("CEL Eval Error (Ignored)", domain.String("rule_id", rule.ID), domain.Any("error", err))
			continue
		}

		if val, ok := out.Value().(bool); ok && val {
			events = append(events, &domain.SecurityEvent{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				Severity:    rule.Severity,
				Message:     "CEL rule matched: " + rule.Expression,
				MatchedData: rule.Expression,
			})
		}
	}

	return events
}

func (e *CelEngine) LoadRules() error {
	if e.rulePath == "" {
		return nil
	}

	f, err := os.Open(e.rulePath)
	if err != nil {
		return fmt.Errorf("failed to open CEL rules: %w", err)
	}
	defer f.Close()

	var rules []CelRule
	if err := json.NewDecoder(f).Decode(&rules); err != nil {
		return fmt.Errorf("failed to decode CEL rules: %w", err)
	}

	for i := range rules {
		ast, iss := e.env.Compile(rules[i].Expression)
		if iss.Err() != nil {
			return fmt.Errorf("failed to compile CEL rule %s: %w", rules[i].ID, iss.Err())
		}

		prg, err := e.env.Program(ast)
		if err != nil {
			return fmt.Errorf("failed to create CEL program %s: %w", rules[i].ID, err)
		}
		rules[i].Program = prg
	}

	e.rules = rules
	e.logger.Info("Loaded CEL rules", domain.Int("count", len(e.rules)))
	return nil
}
