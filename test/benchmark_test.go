package test

import (
	"net/http"
	"testing"

	"github.com/samaasi/go-waf/internal/analysis"
	"github.com/samaasi/go-waf/internal/analysis/engines"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"
)

func BenchmarkWafPipelineFull(b *testing.B) {
	secCfg := &config.SecurityConfig{
		BlockThreshold: 50,
		RateLimit:      100,
		RateLimitWindowSeconds: 1,
	}
	
	acEngine, _ := engines.NewFastMatchEngine("../configs/rules/keywords.json")
	regexEngine := engines.NewRegexEngineWithPath("../configs/rules/regex_rules.json")
	_ = regexEngine.LoadRules()
	mlModel := engines.NewStatisticalModel()
	libInj := engines.NewLibinjectionEngine()
	noopLog := &domain.NoopLogger{}
	celEngine, _ := engines.NewCelEngine("../configs/rules/cel_rules.json", noopLog)
	_ = celEngine.LoadRules()

	pipeline := analysis.NewPipeline(secCfg, noopLog, "../configs/rules/dlp_rules.json", nil, acEngine, regexEngine, mlModel, libInj, celEngine)

	req := &domain.WafRequest{
		ID:        "bench-full",
		Method:    "POST",
		Path:      "/api/v1/resource/search",
		RemoteIP:  "192.168.1.100",
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body: []byte(`{"username": "admin", "payload": "SELECT * FROM users WHERE id=1 OR 1=1"}`),
	}

	resBody := []byte(`{"status": "success", "data": {"card": "4111-1111-1111-1111"}}`)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Inbound
		_, _ = pipeline.Inspect(req)
		// Outbound (DLP)
		_, _, _ = pipeline.InspectResponse(resBody)
	}
}
