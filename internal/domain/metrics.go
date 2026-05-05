package domain

// Metrics defines the interface for recording WAF operational data.
type Metrics interface {
	IncAllow(method, status string)
	IncBlock(method, status string)
	ObserveLatency(method string, duration float64)
	RecordRuleMatch(ruleID, ruleName, severity string)
	RecordGeoIP(countryCode string)
	RecordBot(organization string)
}

type NoopMetrics struct{}

func (n *NoopMetrics) IncAllow(method, status string)           {}
func (n *NoopMetrics) IncBlock(method, status string)           {}
func (n *NoopMetrics) ObserveLatency(method string, duration float64) {}
func (n *NoopMetrics) RecordRuleMatch(ruleID, ruleName, severity string) {}
func (n *NoopMetrics) RecordGeoIP(countryCode string)           {}
func (n *NoopMetrics) RecordBot(organization string)             {}
