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

	ruleEngines, engineCleanups, err := wireRuleEngines(ctx, cfg, log)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("engines: %w", err)
	}
	cleanups = append(cleanups, engineCleanups...)

	pipeline := analysis.NewPipeline(&cfg.Security, log, "./configs/rules/dlp_rules.json", ruleEngines...)

	var geoProv domain.GeoIPProvider
	if cfg.Security.EnableGeoIP {
		if gp, err := geoip.NewMaxMindDB("configs/rules/GeoLite2-Country.mmdb"); err == nil {
			geoProv = gp
			cleanups = append(cleanups, func() { gp.Close() })
			log.Info("GeoIP provider loaded")
		} else {
			log.Warn("GeoIP provider failed to load", domain.Any("error", err))
		}
	}

	adminSvc := admin.NewAdminService(&cfg.Security, pipeline, &cfg.Server, log)

	rateLimiter := ratelimit.NewRedisLimiter(redisClient, log)

	wafMW := middleware.New(pipeline, rateLimiter, &cfg.Security, &cfg.Server, geoProv, log, adminSvc)
	adminHandler := admin.NewAdminHandler(adminSvc)

	watchPaths := []string{
		"./configs/rules/keywords.json",
		"./configs/rules/regex_rules.json",
		"./configs/rules/cel_rules.json",
		"./configs/rules/dlp_rules.json",
		"./configs/rules/openapi.yaml",
	}
	reloadWorker := worker.NewRuleReloadWorker(ruleEngines, watchPaths, 5*time.Minute, log)

	log.Info("Application wired successfully",
		domain.Int("engines", len(ruleEngines)),
		domain.Int("workers", 1),
	)

	return &App{
		Config:       cfg,
		Logger:       log,
		Redis:        redisClient,
		Pipeline:     pipeline,
		AdminSvc:     adminSvc,
		WAF:          wafMW,
		AdminHandler: adminHandler,
		Workers:      []worker.Worker{reloadWorker},
		Cleanup:      cleanup,
	}, nil
}

func wireRuleEngines(ctx context.Context, cfg *config.Config, log domain.Logger) ([]domain.RuleEngine, []func(), error) {
	var ruleEngines []domain.RuleEngine
	var cleanups []func()

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
