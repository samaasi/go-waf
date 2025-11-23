package admin

import (
	"sync"

	"go-waf/internal/analysis"
	"go-waf/internal/config"
)

type AdminService struct {
	config   *config.SecurityConfig
	pipeline *analysis.Pipeline
	mu       sync.RWMutex
}

func NewAdminService(cfg *config.SecurityConfig, pl *analysis.Pipeline) *AdminService {
	return &AdminService{
		config:   cfg,
		pipeline: pl,
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
	// In a real app, fetch this from Redis or Atomic counters
	return map[string]interface{}{
		"status":          "running",
		"block_threshold": s.config.BlockThreshold,
		"mode":            "active_blocking",
	}
}
