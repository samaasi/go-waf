package admin

import (
    "sync"
    "sync/atomic"

    "github.com/samaasi/go-waf/internal/analysis"
    "github.com/samaasi/go-waf/internal/config"
)

type AdminService struct {
    config    *config.SecurityConfig
    serverCfg *config.ServerConfig
    pipeline  *analysis.Pipeline
    mu        sync.RWMutex
    allowedCount atomic.Int64
    blockedCount atomic.Int64
}

func NewAdminService(cfg *config.SecurityConfig, pl *analysis.Pipeline, srv *config.ServerConfig) *AdminService {
    return &AdminService{
        config:    cfg,
        serverCfg: srv,
        pipeline:  pl,
    }
}

// UpdateBlockThreshold changes the sensitivity of the WAF at runtime
func (s *AdminService) UpdateBlockThreshold(newThreshold int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.BlockThreshold = newThreshold
}

// GetStats returns simplified runtime stats
func (s *AdminService) GetStats() map[string]interface{} {
    s.mu.RLock()
    defer s.mu.RUnlock()
    stats := map[string]interface{}{
        "status":                      "running",
        "mode":                        "active_blocking",
        "block_threshold":             s.config.BlockThreshold,
        "rate_limit":                  s.config.RateLimit,
        "rate_limit_window_seconds":   s.config.RateLimitWindowSeconds,
        "geoip_enabled":               s.config.EnableGeoIP,
        "engines_count":               s.pipeline.CountEngines(),
        "allowed_requests":            s.allowedCount.Load(),
        "blocked_requests":            s.blockedCount.Load(),
    }
    if s.serverCfg != nil {
        stats["trusted_proxies_count"] = len(s.serverCfg.TrustedProxies)
        stats["max_body_mb"] = s.serverCfg.MaxBodyMB
        stats["server_mode"] = s.serverCfg.Mode
    }
    return stats
}

func (s *AdminService) IncAllow() { s.allowedCount.Add(1) }
func (s *AdminService) IncBlock() { s.blockedCount.Add(1) }
