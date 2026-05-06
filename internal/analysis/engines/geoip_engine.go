package engines

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"
)

// GeoIPEngine implements the RuleEngine interface using geographic and network intelligence.
type GeoIPEngine struct {
	cfg      *config.SecurityConfig
	provider domain.GeoIPProvider
}

func NewGeoIPEngine(cfg *config.SecurityConfig, provider domain.GeoIPProvider) *GeoIPEngine {
	return &GeoIPEngine{
		cfg:      cfg,
		provider: provider,
	}
}

func (e *GeoIPEngine) ID() string   { return "geoip-intelligence" }
func (e *GeoIPEngine) Name() string { return "GeoIP Intelligence Engine" }

func (e *GeoIPEngine) LoadRules() error {
	// GeoIP rules are loaded from the MaxMind database and config, no separate rule file needed.
	return nil
}

func (e *GeoIPEngine) Evaluate(ctx context.Context, req *domain.WafRequest, phase int) []*domain.SecurityEvent {
	if phase != 1 {
		return nil
	}
	if !e.cfg.EnableGeoIP || e.provider == nil {
		return nil
	}

	res, err := e.provider.Lookup(req.RemoteIP)
	if err != nil {
		return nil
	}

	var events []*domain.SecurityEvent

	// Bot/Data Center Detection
	if res.IsBot {
		events = append(events, &domain.SecurityEvent{
			ID:          uuid.New().String(),
			RequestID:   req.ID,
			RuleID:      "BOT-001",
			RuleName:    "Bot/DataCenter Detected",
			Severity:    domain.SeverityMedium,
			Message:     fmt.Sprintf("Request from known data center/hosting provider: %s", res.Organization),
			MatchedData: res.Organization,
			Timestamp:   time.Now(),
		})
	}

	// Country Blocking
	if slices.Contains(e.cfg.BlockCountries, res.CountryCode) {
		events = append(events, &domain.SecurityEvent{
			ID:          uuid.New().String(),
			RequestID:   req.ID,
			RuleID:      "GEO-101",
			RuleName:    "Country Blocked",
			Severity:    domain.SeverityHigh,
			Message:     fmt.Sprintf("Access denied for country: %s", res.CountryCode),
			MatchedData: res.CountryCode,
			Timestamp:   time.Now(),
		})
	}

	// Country Allow-listing (Negative match)
	if len(e.cfg.AllowCountries) > 0 && !slices.Contains(e.cfg.AllowCountries, res.CountryCode) {
		events = append(events, &domain.SecurityEvent{
			ID:          uuid.New().String(),
			RequestID:   req.ID,
			RuleID:      "GEO-102",
			RuleName:    "Country Not Allowed",
			Severity:    domain.SeverityHigh,
			Message:     fmt.Sprintf("Country %s is not in the allow-list", res.CountryCode),
			MatchedData: res.CountryCode,
			Timestamp:   time.Now(),
		})
	}

	return events
}
