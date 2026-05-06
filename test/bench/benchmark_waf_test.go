package bench

import (
	"context"
	"net/http"
	"testing"

	"os"

	"github.com/samaasi/go-waf/internal/analysis"
	"github.com/samaasi/go-waf/internal/analysis/engines"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/internal/platform/logger"
	"github.com/samaasi/go-waf/internal/platform/telemetry"
	"github.com/samaasi/go-waf/internal/store"
	"github.com/samaasi/go-waf/internal/worker"
	"go.uber.org/zap"
)

func BenchmarkPipelineInspect(b *testing.B) {
	log := logger.NewZapAdapter(zap.NewNop())
	cfg := &config.SecurityConfig{BlockThreshold: 5}
	mockStore := store.NewMockCollectionStore()

	// Fast Match Engine (Aho-Corasick)
	sigEngine, _ := engines.NewFastMatchEngine("../../configs/rules/keywords.json")
	_ = sigEngine.LoadRules()

	// CRS Engine (Stateful Rules)
	crsEngine := engines.NewCRSLangEngine("../../configs/rules/persistence.yaml", mockStore)
	_ = crsEngine.LoadRules()

	pipeline := analysis.NewPipeline(cfg, log, "", nil, sigEngine, crsEngine)

	req := &domain.WafRequest{
		ID:       "bench-id",
		Method:   "GET",
		Path:     "/trigger",
		RemoteIP: "1.2.3.4",
		Headers:  http.Header{"User-Agent": []string{"Mozilla/5.0"}},
		TX:       make(map[string]interface{}),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req.TX = make(map[string]interface{}) // Reset TX state per iteration
		_, _ = pipeline.Inspect(context.Background(), req)
	}
}

func BenchmarkMacroExpansion(b *testing.B) {
	crsEngine := engines.NewCRSLangEngine("", nil)
	req := &domain.WafRequest{
		TX: map[string]interface{}{
			"score": 10,
			"ip":    "127.0.0.1",
		},
	}

	input := "Matching score %{tx.score} from IP %{tx.ip}"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = crsEngine.ExpandMacros(input, req)
	}
}

func BenchmarkPipelineWithAuditLog(b *testing.B) {
	log := logger.NewZapAdapter(zap.NewNop())
	cfg := &config.SecurityConfig{BlockThreshold: 5}
	mockStore := store.NewMockCollectionStore()

	// Setup Audit Worker
	auditPath := "bench_audit.log"
	auditWorker := worker.NewAuditWorker(auditPath, 1000, log)
	go auditWorker.Start(context.Background())
	defer os.Remove(auditPath)

	exporter := telemetry.NewLocalAuditExporter(auditWorker.GetQueue())

	// 1. Fast Match Engine
	sigEngine, _ := engines.NewFastMatchEngine("../../configs/rules/keywords.json")
	_ = sigEngine.LoadRules()

	// 2. CRS Engine
	crsEngine := engines.NewCRSLangEngine("../../configs/rules/persistence.yaml", mockStore)
	_ = crsEngine.LoadRules()

	pipeline := analysis.NewPipeline(cfg, log, "", exporter, sigEngine, crsEngine)

	req := &domain.WafRequest{
		ID:       "bench-id",
		Method:   "GET",
		Path:     "/trigger", // This will trigger both rules
		RemoteIP: "1.2.3.4",
		TX:       make(map[string]interface{}),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req.TX = make(map[string]interface{})
		_, events := pipeline.Inspect(context.Background(), req)
		pipeline.FinishTransaction(req, events)
	}
}
