package worker

import (
	"context"
	"time"

	"github.com/samaasi/go-waf/internal/domain"
)

type Worker interface {
	Start(ctx context.Context) error
}


type RuleReloadWorker struct {
	engines  []domain.RuleEngine
	interval time.Duration
	logger   domain.Logger
}

// NewRuleReloadWorker creates a worker that reloads rules every `interval`.
func NewRuleReloadWorker(engines []domain.RuleEngine, interval time.Duration, log domain.Logger) *RuleReloadWorker {
	return &RuleReloadWorker{
		engines:  engines,
		interval: interval,
		logger:   log,
	}
}

// Start runs the reload loop until the context is cancelled.
func (w *RuleReloadWorker) Start(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	w.logger.Info("RuleReloadWorker started", domain.Any("interval", w.interval.String()))

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("RuleReloadWorker shutting down")
			return nil
		case <-ticker.C:
			w.reloadAll()
		}
	}
}

func (w *RuleReloadWorker) reloadAll() {
	for _, engine := range w.engines {
		if err := engine.LoadRules(); err != nil {
			w.logger.Error("Failed to reload rules", domain.Any("error", err))
		}
	}
	w.logger.Debug("Rules reloaded successfully")
}
