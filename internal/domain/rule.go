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

// RuleMetadata provides a unified view of a rule's configuration and status.
type RuleMetadata struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    Severity `json:"severity"`
	Tags        []string `json:"tags"`
	Enabled     bool     `json:"enabled"`
	EngineID    string   `json:"engine_id"`
	Description string   `json:"description,omitempty"`
}

// RuleEngine describes a component that can manage and execute a set of rules.
type RuleEngine interface {
	ID() string
	Name() string
	LoadRules() error
	GetRules() []RuleMetadata
	ToggleRule(id string, enabled bool) bool
	Evaluate(ctx context.Context, req *WafRequest, phase int) []*SecurityEvent
}
