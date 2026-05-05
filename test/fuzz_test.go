package test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/samaasi/go-waf/internal/analysis"
	"github.com/samaasi/go-waf/internal/analysis/engines"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/pkg/utils"
)

func FuzzNormalize(f *testing.F) {
	f.Add("normal text")
	f.Add("%2555nion%20select")
	f.Add("&lt;script&gt;alert(1)&lt;/script&gt;")
	f.Add("\u200BUNION\u200BSELECT")
	f.Add(string([]byte{0x00, 0x01, 0xFF, 0xFE}))

	f.Fuzz(func(t *testing.T, input string) {
		result := utils.NormalizeString(input)
		// Must not panic and must return a valid string
		_ = len(result)
	})
}

func FuzzExtractValuesOnly(f *testing.F) {
	f.Add([]byte(`{"key": "value"}`))
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte(`{`))
	f.Add([]byte(`{"nested": {"deep": "val"}}`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, input []byte) {
		result := utils.ExtractValuesOnly(input)
		_ = len(result)
	})
}

func FuzzPipelineInspect(f *testing.F) {
	f.Add([]byte(`normal request body`))
	f.Add([]byte(`{"user": "admin' OR 1=1--"}`))
	f.Add([]byte(`<script>alert(document.cookie)</script>`))
	f.Add([]byte{})

	secCfg := &config.SecurityConfig{BlockThreshold: 50, RateLimit: 100, RateLimitWindowSeconds: 1}
	noopLog := &domain.NoopLogger{}
	re := engines.NewRegexEngineWithPath("../configs/rules/regex_rules.json")
	_ = re.LoadRules()
	ml := engines.NewStatisticalModel()
	pipeline := analysis.NewPipeline(secCfg, noopLog, "../configs/rules/dlp_rules.json", nil, re, ml)

	f.Fuzz(func(t *testing.T, body []byte) {
		req := &domain.WafRequest{
			ID:        "fuzz-test",
			Method:    "POST",
			Path:      "/api/test",
			RemoteIP:  "10.0.0.1",
			Headers:   http.Header{"Content-Type": []string{"application/json"}},
			QueryArgs: url.Values{},
			Body:      body,
			Protocol:  "HTTP/1.1",
		}
		// Must not panic
		_, _ = pipeline.Inspect(req)
	})
}
