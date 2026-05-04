package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/samaasi/go-waf/internal/admin"
	"github.com/samaasi/go-waf/internal/analysis"
	"github.com/samaasi/go-waf/internal/analysis/engines"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/internal/middleware"
	"github.com/samaasi/go-waf/internal/platform/cache"
	"github.com/samaasi/go-waf/internal/platform/geoip"
	"github.com/samaasi/go-waf/internal/platform/logger"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func main() {
	cfg, err := config.LoadConfig(".")
	if err != nil {
		panic("Failed to load config: " + err.Error())
	}

	logger.Init(cfg.Log.Level)
	// Create the domain logger adapter
	domainLogger := logger.NewZapAdapter(logger.Log)

	domainLogger.Info("Starting WAF Server...")

	redisClient := cache.NewRedisClient(cfg.Redis)

	acEngine, err := engines.NewFastMatchEngine("./configs/rules/keywords.json")
	if err != nil {
		logger.Log.Fatal("Failed to load keyword rules", zap.Error(err))
	}

	regexEngine := engines.NewRegexEngineWithPath("./configs/rules/regex_rules.json")
	_ = regexEngine.LoadRules()
	mlModel := engines.NewStatisticalModel()
	libInj := engines.NewLibinjectionEngine()
	celEngine, _ := engines.NewCelEngine("./configs/rules/cel_rules.json", domainLogger)
	_ = celEngine.LoadRules()

	var ruleEngines []domain.RuleEngine
	ruleEngines = append(ruleEngines, acEngine, regexEngine, mlModel, libInj, celEngine)

	// Optional: Load WASM Plugin Engine if a plugin exists
	wasmPath := "./plugins/security_v1.wasm"
	if _, err := os.Stat(wasmPath); err == nil {
		if wasmEngine, err := engines.NewWasmEngine(context.Background(), wasmPath, domainLogger); err == nil {
			ruleEngines = append(ruleEngines, wasmEngine)
			domainLogger.Info("Loaded WASM Plugin Engine", domain.String("path", wasmPath))
		}
	}

	pipeline := analysis.NewPipeline(&cfg.Security, domainLogger, ruleEngines...)

	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := routeSetup(pipeline, redisClient, &cfg.Security, &cfg.Server, domainLogger)

	addr := fmt.Sprintf(":%s", cfg.Server.Port)
	domainLogger.Info("Server listening", domain.String("addr", addr))
	if err := http.ListenAndServe(addr, r); err != nil {
		logger.Log.Fatal("Server failed", zap.Error(err))
	}
}

func routeSetup(pipeline *analysis.Pipeline, redisClient *cache.RedisClient, secCfg *config.SecurityConfig, srvCfg *config.ServerConfig, log domain.Logger) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	if len(srvCfg.TrustedProxies) > 0 {
		_ = r.SetTrustedProxies(srvCfg.TrustedProxies)
	}

	var geoProv domain.GeoIPProvider
	if secCfg.EnableGeoIP {
		if gp, err := geoip.NewMaxMindDB("configs/rules/GeoLite2-Country.mmdb"); err == nil {
			geoProv = gp
		}
	}

	adminSvc := admin.NewAdminService(secCfg, pipeline, srvCfg)
	wafMiddleware := middleware.New(pipeline, redisClient, secCfg, srvCfg, geoProv, log, adminSvc)
	r.Use(wafMiddleware.Handler())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	r.POST("/api/login", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Login successful"})
	})

    adminHandler := admin.NewAdminHandler(adminSvc)
    adminHandler.RegisterRoutes(r.Group("/"))

	return r
}
