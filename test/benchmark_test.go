package test

import (
	"net/http"
	"net/url"
	"testing"

	"go-waf/internal/analysis"
	"go-waf/internal/analysis/engines"
	"go-waf/internal/config"
	"go-waf/internal/domain"
)

func BenchmarkWafPipeline(b *testing.B) {
	secCfg := &config.SecurityConfig{BlockThreshold: 50}
	
	acEngine, _ := engines.NewFastMatchEngine("../configs/rules/keywords.json")
	regexEngine := engines.NewRegexEngineWithPath("../configs/rules/regex_rules.json")
	_ = regexEngine.LoadRules()
	mlModel := engines.NewStatisticalModel()
	libInj := engines.NewLibinjectionEngine()

	pipeline := analysis.NewPipeline(secCfg, acEngine, regexEngine, mlModel, libInj)

	req := &domain.WafRequest{
		ID:        "bench-123",
		Method:    "POST",
		Path:      "/api/v1/resource/search",
		RemoteIP:  "192.168.1.100",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		Headers: http.Header{
			"Accept":          []string{"application/json"},
			"Content-Type":    []string{"application/json"},
			"X-Forwarded-For": []string{"10.0.0.1"},
		},
		QueryArgs: url.Values{
			"q":    []string{"search_term"},
			"sort": []string{"desc"},
		},
		Body: []byte(`{"username": "admin", "action": "delete", "target": "user_profile", "metadata": {"origin": "web"}}`),
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = pipeline.Inspect(req)
	}
}
