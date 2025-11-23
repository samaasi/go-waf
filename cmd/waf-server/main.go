package main

import (
	"fmt"
	"net/http"

	"go-waf/internal/analysis"
	"go-waf/internal/analysis/engines"
	"go-waf/internal/config"
	"go-waf/internal/middleware"
	"go-waf/internal/platform/cache"
	"go-waf/internal/platform/logger"

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

	regexEngine := engines.NewRegexEngine()

	pipeline := analysis.NewPipeline(&cfg.Security, regexEngine)

	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := routeSetup(pipeline, redisClient, &cfg.Security)

	addr := fmt.Sprintf(":%s", cfg.Server.Port)
	logger.Log.Info("Server listening", zap.String("addr", addr))
	if err := http.ListenAndServe(addr, r); err != nil {
		logger.Log.Fatal("Server failed", zap.Error(err))
	}
}

func routeSetup(pipeline *analysis.Pipeline, redisClient *cache.RedisClient, secCfg *config.SecurityConfig) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	wafMiddleware := middleware.New(pipeline, redisClient, secCfg)
	r.Use(wafMiddleware.Handler())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	r.POST("/api/login", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Login successful"})
	})

	return r
}
