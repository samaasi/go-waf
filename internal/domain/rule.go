package domain

// Rule represents a single detection logic unit.
type Rule interface {
	ID() string
	Name() string
	Tags() []string
	Evaluate(req *WafRequest) (bool, string)
	Severity() Severity
}

// RuleEngine describes a component that can manage and execute a set of rules.
type RuleEngine interface {
	ID() string
	Name() string
	LoadRules() error
	Evaluate(req *WafRequest) []*SecurityEvent
}
