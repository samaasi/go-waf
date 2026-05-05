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

func NewRuleReloadWorker(engines []domain.RuleEngine, watchPaths []string, interval time.Duration, log domain.Logger) *RuleReloadWorker {
	return &RuleReloadWorker{
		engines:    engines,
		watchPaths: watchPaths,
		interval:   interval,
		logger:     log,
	}
}

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

	// Debounce rapid file changes (editors often write multiple times)
	var debounceTimer *time.Timer

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
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(2*time.Second, func() {
					w.reloadAll()
				})
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
	failed := 0
	for _, engine := range w.engines {
		if err := engine.LoadRules(); err != nil {
			w.logger.Error("Failed to reload rules for engine — keeping previous rules",
				domain.Any("error", err),
			)
			failed++
		}
	}
	if failed == 0 {
		w.logger.Debug("Rules reloaded successfully")
	} else {
		w.logger.Warn("Partial rule reload",
			domain.Int("failed", failed),
			domain.Int("total", len(w.engines)),
		)
	}
}
