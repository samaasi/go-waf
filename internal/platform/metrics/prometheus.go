package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waf_requests_total",
			Help: "The total number of requests processed by the WAF",
		},
		[]string{"action", "method", "status"},
	)

	RequestLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "waf_request_latency_seconds",
			Help:    "Request latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method"},
	)

	RuleMatches = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waf_rule_matches_total",
			Help: "The total number of rule matches",
		},
		[]string{"rule_id", "rule_name", "severity"},
	)

	GeoIPRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waf_geoip_requests_total",
			Help: "The total number of requests by country",
		},
		[]string{"country_code"},
	)
	
	BotRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waf_bot_requests_total",
			Help: "The total number of requests detected as bots",
		},
		[]string{"organization"},
	)
)

type PrometheusMetrics struct{}

func NewPrometheusMetrics() *PrometheusMetrics {
	return &PrometheusMetrics{}
}

func (m *PrometheusMetrics) IncAllow(method, status string) {
	RequestsTotal.WithLabelValues("allow", method, status).Inc()
}

func (m *PrometheusMetrics) IncBlock(method, status string) {
	RequestsTotal.WithLabelValues("block", method, status).Inc()
}

func (m *PrometheusMetrics) ObserveLatency(method string, duration float64) {
	RequestLatency.WithLabelValues(method).Observe(duration)
}

func (m *PrometheusMetrics) RecordRuleMatch(ruleID, ruleName, severity string) {
	RuleMatches.WithLabelValues(ruleID, ruleName, severity).Inc()
}

func (m *PrometheusMetrics) RecordGeoIP(countryCode string) {
	GeoIPRequests.WithLabelValues(countryCode).Inc()
}

func (m *PrometheusMetrics) RecordBot(organization string) {
	BotRequests.WithLabelValues(organization).Inc()
}
