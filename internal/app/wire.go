package app

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/samaasi/go-waf/internal/admin"
	"github.com/samaasi/go-waf/internal/analysis"
	"github.com/samaasi/go-waf/internal/analysis/engines"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/internal/middleware"
	"github.com/samaasi/go-waf/internal/platform/geoip"
	"github.com/samaasi/go-waf/internal/platform/metrics"
	"github.com/samaasi/go-waf/internal/platform/telemetry"
	"github.com/samaasi/go-waf/internal/ratelimit"
	"github.com/samaasi/go-waf/internal/store"
	"github.com/samaasi/go-waf/internal/worker"
)

func Wire(ctx context.Context, cfg *config.Config, log domain.Logger) (*App, error) {
	var cleanups []func()
	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}

	redisClient, err := store.NewRedisClient(cfg.Redis, log)
	if err != nil {
		return nil, fmt.Errorf("redis: %w", err)
	}
	cleanups = append(cleanups, func() {
		if err := redisClient.Close(); err != nil {
			log.Error("Redis close error", domain.Any("error", err))
		}
	})

	var geoProv domain.GeoIPProvider
	if cfg.Security.EnableGeoIP {
		cityPath := "configs/geoip/GeoLite2-City.mmdb"
		asnPath := "configs/geoip/GeoLite2-ASN.mmdb"
		if gp, err := geoip.NewMaxMindDB(cityPath, asnPath); err == nil {
			geoProv = gp
			cleanups = append(cleanups, func() { gp.Close() })
			log.Info("GeoIP provider loaded (City + ASN)")
		} else {
			log.Warn("GeoIP provider failed to load, falling back to mock", domain.Any("error", err))
			geoProv = &geoip.MockProvider{}
		}
	}

	colStore := store.NewRedisCollectionStore(redisClient)

	ruleEngines, engineCleanups, err := wireRuleEngines(ctx, cfg, geoProv, colStore, log)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("engines: %w", err)
	}
	cleanups = append(cleanups, engineCleanups...)

	var workers []worker.Worker
	auditQueueSize := 1000
	auditWorker := worker.NewAuditWorker("configs/audit.log", auditQueueSize, log)
	workers = append(workers, auditWorker)

	localExporter := telemetry.NewLocalAuditExporter(auditWorker.GetQueue())
	var exporter domain.AuditExporter = localExporter

	if cfg.Telemetry.Enabled {
		cloudExporter := telemetry.NewCloudExporter(1000, log)
		telemetryWorker := worker.NewTelemetryWorker(&cfg.Telemetry, cloudExporter.GetQueue(), log)
		workers = append(workers, telemetryWorker)

		// Combine both into a MultiExporter
		exporter = telemetry.NewMultiExporter(localExporter, cloudExporter)
		log.Info("Telemetry dual-export enabled (Local Audit + Cloud)", domain.String("collector", cfg.Telemetry.CollectorURL))
	}

	pipeline := analysis.NewPipeline(&cfg.Security, log, "./configs/rules/dlp_rules.json", exporter, ruleEngines...)

	if cfg.Security.EnableGeoIP && geoProv != nil {
		geoipWorker := worker.NewGeoIPWorker(cfg, geoProv, log)
		workers = append(workers, geoipWorker)
	}

	k8sWorker := worker.NewK8sOperatorWorker(pipeline, log)
	workers = append(workers, k8sWorker)

	adminSvc := admin.NewAdminService(&cfg.Security, pipeline, &cfg.Server, log)
	promMetrics := metrics.NewPrometheusMetrics()

	multiMetrics := MultiMetrics{adminSvc, promMetrics}

	rateLimiter := ratelimit.NewRedisLimiter(redisClient, log)

	wafMW := middleware.New(pipeline, rateLimiter, &cfg.Security, &cfg.Server, geoProv, log, multiMetrics)
	adminHandler := admin.NewAdminHandler(adminSvc)

	watchPaths := []string{
		"./configs/rules/keywords.json",
		"./configs/rules/regex_rules.json",
		"./configs/rules/cel_rules.json",
		"./configs/rules/dlp_rules.json",
		"./configs/rules/openapi.yaml",
		"./configs/geoip/GeoLite2-City.mmdb",
		"./configs/geoip/GeoLite2-ASN.mmdb",
	}
	reloadWorker := worker.NewRuleReloadWorker(ruleEngines, watchPaths, 5*time.Minute, log)
	workers = append(workers, reloadWorker)

	log.Info("Application wired successfully",
		domain.Int("engines", len(ruleEngines)),
		domain.Int("workers", len(workers)),
	)

	return &App{
		Config:       cfg,
		Logger:       log,
		Redis:        redisClient,
		Pipeline:     pipeline,
		AdminSvc:     adminSvc,
		WAF:          wafMW,
		AdminHandler: adminHandler,
		Workers:      workers,
		Cleanup:      cleanup,
	}, nil
}

func wireRuleEngines(ctx context.Context, cfg *config.Config, geo domain.GeoIPProvider, colStore domain.CollectionStore, log domain.Logger) ([]domain.RuleEngine, []func(), error) {
	var ruleEngines []domain.RuleEngine
	var cleanups []func()

	if cfg.Security.EnableGeoIP && geo != nil {
		ruleEngines = append(ruleEngines, engines.NewGeoIPEngine(&cfg.Security, geo))
	}

	acEngine, err := engines.NewFastMatchEngine("./configs/rules/keywords.json")
	if err != nil {
		return nil, nil, fmt.Errorf("aho-corasick engine: %w", err)
	}
	ruleEngines = append(ruleEngines, acEngine)

	regexEngine := engines.NewRegexEngineWithPath("./configs/rules/regex_rules.json")
	if err := regexEngine.LoadRules(); err != nil {
		log.Warn("Regex rules load warning", domain.Any("error", err))
	}
	ruleEngines = append(ruleEngines, regexEngine)

	mlModel := engines.NewStatisticalModel()
	ruleEngines = append(ruleEngines, mlModel)

	libInj := engines.NewLibinjectionEngine()
	ruleEngines = append(ruleEngines, libInj)

	celEngine, err := engines.NewCelEngine("./configs/rules/cel_rules.json", log)
	if err != nil {
		log.Warn("CEL engine init warning", domain.Any("error", err))
	} else {
		if err := celEngine.LoadRules(); err != nil {
			log.Warn("CEL rules load warning", domain.Any("error", err))
		}
		ruleEngines = append(ruleEngines, celEngine)
	}

	if cfg.Security.EnableSchemaValidation {
		schemaEngine := engines.NewSchemaEngine(cfg.Security.OpenAPISchemaPath, log)
		if err := schemaEngine.LoadRules(); err != nil {
			log.Warn("Schema engine load warning", domain.Any("error", err))
		} else {
			ruleEngines = append(ruleEngines, schemaEngine)
		}
	}

	crsEngine := engines.NewCRSLangEngine("./configs/rules/owasp-crs", colStore)
	if err := crsEngine.LoadRules(); err != nil {
		log.Warn("CRSLang engine rules load warning", domain.Any("error", err))
	} else {
		ruleEngines = append(ruleEngines, crsEngine)
	}

	wasmPath := "./plugins/security_v1.wasm"
	if _, statErr := os.Stat(wasmPath); statErr == nil {
		if wasmEngine, wasmErr := engines.NewWasmEngine(ctx, wasmPath, log); wasmErr == nil {
			ruleEngines = append(ruleEngines, wasmEngine)
			cleanups = append(cleanups, func() { _ = wasmEngine.Close() })
			log.Info("WASM plugin loaded", domain.String("path", wasmPath))
		} else {
			log.Warn("WASM plugin failed to load", domain.Any("error", wasmErr))
		}
	}

	return ruleEngines, cleanups, nil
}

type MultiMetrics []domain.Metrics

func (m MultiMetrics) IncAllow(method, status string) {
	for _, p := range m {
		p.IncAllow(method, status)
	}
}

func (m MultiMetrics) IncBlock(method, status string) {
	for _, p := range m {
		p.IncBlock(method, status)
	}
}

func (m MultiMetrics) ObserveLatency(method string, duration float64) {
	for _, p := range m {
		p.ObserveLatency(method, duration)
	}
}

func (m MultiMetrics) RecordRuleMatch(ruleID, ruleName, severity string) {
	for _, p := range m {
		p.RecordRuleMatch(ruleID, ruleName, severity)
	}
}

func (m MultiMetrics) RecordGeoIP(countryCode string) {
	for _, p := range m {
		p.RecordGeoIP(countryCode)
	}
}

func (m MultiMetrics) RecordBot(organization string) {
	for _, p := range m {
		p.RecordBot(organization)
	}
}
