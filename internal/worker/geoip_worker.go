package worker

import (
	"context"
	"time"

	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/internal/platform/geoip"
)

type GeoIPWorker struct {
	cfg      *config.Config
	provider domain.GeoIPProvider
	logger   domain.Logger
}

func NewGeoIPWorker(cfg *config.Config, provider domain.GeoIPProvider, logger domain.Logger) *GeoIPWorker {
	return &GeoIPWorker{
		cfg:      cfg,
		provider: provider,
		logger:   logger,
	}
}

func (w *GeoIPWorker) Start(ctx context.Context) error {
	if w.cfg.Security.MaxMindLicenseKey == "" {
		w.logger.Warn("GeoIP updates disabled: missing MaxMind license key")
		return nil
	}

	w.logger.Info("GeoIPWorker started", domain.Int("interval_hours", w.cfg.Security.GeoIPUpdateIntervalHours))

	ticker := time.NewTicker(time.Duration(w.cfg.Security.GeoIPUpdateIntervalHours) * time.Hour)
	defer ticker.Stop()

	// Initial check on startup
	w.performUpdate()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			w.performUpdate()
		}
	}
}

func (w *GeoIPWorker) performUpdate() {
	updatedCity, err := geoip.EnsureDatabase("GeoLite2-City", w.cfg.Security.MaxMindLicenseKey, "configs/geoip/GeoLite2-City.mmdb", w.logger)
	if err != nil {
		w.logger.Error("Failed to update GeoLite2-City", domain.Any("error", err))
	}

	updatedASN, err := geoip.EnsureDatabase("GeoLite2-ASN", w.cfg.Security.MaxMindLicenseKey, "configs/geoip/GeoLite2-ASN.mmdb", w.logger)
	if err != nil {
		w.logger.Error("Failed to update GeoLite2-ASN", domain.Any("error", err))
	}

	if updatedCity || updatedASN {
		w.logger.Info("GeoIP databases updated, reloading provider...")
		if err := w.provider.Reload(); err != nil {
			w.logger.Error("Failed to reload GeoIP provider", domain.Any("error", err))
		} else {
			w.logger.Info("GeoIP provider reloaded successfully")
		}
	}
}
