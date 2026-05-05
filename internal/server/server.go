package server

import (
	"github.com/samaasi/go-waf/internal/admin"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/middleware"

	"github.com/gin-gonic/gin"
)

func NewRouter(wafMW *middleware.WafMiddleware, adminHandler *admin.AdminHandler, srvCfg *config.ServerConfig) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	if len(srvCfg.TrustedProxies) > 0 {
		_ = r.SetTrustedProxies(srvCfg.TrustedProxies)
	}

	// Security headers on every response
	r.Use(middleware.SecurityHeaders())

	// Global WAF inspection middleware
	r.Use(wafMW.Handler())

	// Proxy Mode logic
	if srvCfg.EnableProxy && srvCfg.ProxyTarget != "" {
		// Inject WAF insights into upstream headers
		r.Use(InsightHeadersMiddleware())
		
		// Catch-all route for proxying
		r.NoRoute(ProxyHandler(srvCfg.ProxyTarget, wafMW.GetLogger()))
	}

	// Infrastructure routes
	r.GET("/health", HealthHandler())

	// Domain routes
	adminGroup := r.Group("/")
	adminGroup.Use(middleware.AdminAuth(srvCfg.AdminAPIKey))
	adminHandler.RegisterRoutes(adminGroup)

	return r
}
