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

func ParseSeverity(s string) Severity {
	switch s {
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityMedium
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
	MatchedData string            `json:"matched_data"`
	MatchedVars map[string]string `json:"matched_vars,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	RemoteIP    string            `json:"remote_ip,omitempty"`
	Path        string            `json:"path,omitempty"`
	Method      string            `json:"method,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
}

// AuditExporter defines the interface for streaming security events.
type AuditExporter interface {
	Export(events ...*SecurityEvent)
	LogTransaction(req *WafRequest, events []*SecurityEvent)
}

// NoopAuditExporter is the default "opt-out" implementation.
type NoopAuditExporter struct{}

func (n *NoopAuditExporter) Export(events ...*SecurityEvent) {}
func (n *NoopAuditExporter) LogTransaction(req *WafRequest, events []*SecurityEvent) {}
