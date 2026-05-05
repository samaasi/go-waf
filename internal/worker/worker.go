package worker

import (
	"context"
	"time"

	"github.com/samaasi/go-waf/internal/domain"

	"github.com/fsnotify/fsnotify"
)

type Worker interface {
	Start(ctx context.Context) error
}


type RuleReloadWorker struct {
	engines    []domain.RuleEngine
	watchPaths []string
	interval   time.Duration
	logger     domain.Logger
}

// NewRuleReloadWorker creates a worker that reloads rules every `interval`.
func NewRuleReloadWorker(engines []domain.RuleEngine, watchPaths []string, interval time.Duration, log domain.Logger) *RuleReloadWorker {
	return &RuleReloadWorker{
		engines:    engines,
		watchPaths: watchPaths,
		interval:   interval,
		logger:     log,
	}
}

// Start runs the reload loop until the context is cancelled.
func (w *RuleReloadWorker) Start(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	for _, path := range w.watchPaths {
		if err := watcher.Add(path); err != nil {
			w.logger.Warn("Failed to watch rule file", domain.String("path", path), domain.Any("error", err))
		}
	}

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	w.logger.Info("RuleReloadWorker started", domain.Int("watching", len(w.watchPaths)))

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				w.logger.Info("Rule file change detected", domain.String("file", event.Name))
				w.reloadAll()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			w.logger.Error("Watcher error", domain.Any("error", err))
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
