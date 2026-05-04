package main

import (
	"fmt"
	"net/http"

	"github.com/samaasi/go-waf/internal/admin"
	"github.com/samaasi/go-waf/internal/analysis"
	"github.com/samaasi/go-waf/internal/analysis/engines"
	"github.com/samaasi/go-waf/internal/config"
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
	logger.Log.Info("Starting WAF Server...")

	redisClient := cache.NewRedisClient(cfg.Redis)

    acEngine, err := engines.NewFastMatchEngine("./configs/rules/keywords.json")
    if err != nil {
        logger.Log.Fatal("Failed to load keyword rules", zap.Error(err))
    }

	regexEngine := engines.NewRegexEngineWithPath("./configs/rules/regex_rules.json")
	_ = regexEngine.LoadRules()
	mlModel := engines.NewStatisticalModel()
	libInj := engines.NewLibinjectionEngine()
	celEngine, _ := engines.NewCelEngine("./configs/rules/cel_rules.json")
	_ = celEngine.LoadRules()

	pipeline := analysis.NewPipeline(&cfg.Security, acEngine, regexEngine, mlModel, libInj, celEngine)

	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := routeSetup(pipeline, redisClient, &cfg.Security, &cfg.Server)

	addr := fmt.Sprintf(":%s", cfg.Server.Port)
	logger.Log.Info("Server listening", zap.String("addr", addr))
	if err := http.ListenAndServe(addr, r); err != nil {
		logger.Log.Fatal("Server failed", zap.Error(err))
	}
}

func routeSetup(pipeline *analysis.Pipeline, redisClient *cache.RedisClient, secCfg *config.SecurityConfig, srvCfg *config.ServerConfig) *gin.Engine {
    r := gin.New()
    r.Use(gin.Recovery())
    if len(srvCfg.TrustedProxies) > 0 {
        _ = r.SetTrustedProxies(srvCfg.TrustedProxies)
    }

    var geoProv geoip.GeoIPProvider
    if secCfg.EnableGeoIP {
        if gp, err := geoip.NewMaxMindDB("configs/rules/GeoLite2-Country.mmdb"); err == nil {
            geoProv = gp
        }
    }

    adminSvc := admin.NewAdminService(secCfg, pipeline, srvCfg)
    wafMiddleware := middleware.New(pipeline, redisClient, secCfg, srvCfg, geoProv, adminSvc)
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
