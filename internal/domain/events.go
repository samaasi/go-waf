package domain

import (
	"time"
)

// Severity indicates the risk level of a rule match.
type Severity int

const (
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 5
	SeverityHigh     Severity = 10
	SeverityCritical Severity = 25
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// SecurityEvent represents a specific rule violation.
type SecurityEvent struct {
	ID          string    `json:"id"`
	RequestID   string    `json:"request_id"`
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	Severity    Severity  `json:"severity"`
	Message     string    `json:"message"`
	MatchedData string    `json:"matched_data"`
	Timestamp   time.Time `json:"timestamp"`
}

// AuditExporter defines the interface for streaming security events.
type AuditExporter interface {
	Export(events ...*SecurityEvent)
}

// NoopAuditExporter is the default "opt-out" implementation.
type NoopAuditExporter struct{}

func (n *NoopAuditExporter) Export(events ...*SecurityEvent) {}
