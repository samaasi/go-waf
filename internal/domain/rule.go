package domain

import (
	"context"
)

// Rule represents a single detection logic unit.
type Rule interface {
	ID() string
	Name() string
	Tags() []string
	Evaluate(ctx context.Context, req *WafRequest) (bool, string)
	Severity() Severity
}

// RuleEngine describes a component that can manage and execute a set of rules.
type RuleEngine interface {
	ID() string
	Name() string
	LoadRules() error
	Evaluate(ctx context.Context, req *WafRequest, phase int) []*SecurityEvent
}
