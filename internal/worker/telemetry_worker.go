package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"
)

type TelemetryWorker struct {
	cfg        *config.TelemetryConfig
	queue      <-chan *domain.SecurityEvent
	logger     domain.Logger
	httpClient *http.Client
}

func NewTelemetryWorker(cfg *config.TelemetryConfig, queue <-chan *domain.SecurityEvent, logger domain.Logger) *TelemetryWorker {
	return &TelemetryWorker{
		cfg:    cfg,
		queue:  queue,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (w *TelemetryWorker) Start(ctx context.Context) error {
	w.logger.Info("TelemetryWorker started",
		domain.String("collector", w.cfg.CollectorURL),
		domain.Int("batch_size", w.cfg.BatchSize),
	)

	ticker := time.NewTicker(time.Duration(w.cfg.FlushInterval) * time.Millisecond)
	defer ticker.Stop()

	var batch []*domain.SecurityEvent

	for {
		select {
		case <-ctx.Done():
			if len(batch) > 0 {
				w.flush(batch)
			}
			return nil
		case event := <-w.queue:
			batch = append(batch, event)
			if len(batch) >= w.cfg.BatchSize {
				w.flush(batch)
				batch = nil
			}
		case <-ticker.C:
			if len(batch) > 0 {
				w.flush(batch)
				batch = nil
			}
		}
	}
}

func (w *TelemetryWorker) flush(batch []*domain.SecurityEvent) {
	payload := struct {
		OrganizationID string                  `json:"organization_id"`
		Events         []*domain.SecurityEvent `json:"events"`
	}{
		OrganizationID: w.cfg.OrganizationID,
		Events:         batch,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		w.logger.Error("Failed to marshal telemetry batch", domain.Any("error", err))
		return
	}

	req, err := http.NewRequest(http.MethodPost, w.cfg.CollectorURL, bytes.NewBuffer(body))
	if err != nil {
		w.logger.Error("Failed to create telemetry request", domain.Any("error", err))
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", w.cfg.APIKey)

	resp, err := w.httpClient.Do(req)
	if err != nil {
		w.logger.Error("Failed to send telemetry batch", domain.Any("error", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		w.logger.Warn("Telemetry collector returned error",
			domain.Int("status", resp.StatusCode),
			domain.Int("batch_size", len(batch)),
		)
		return
	}

	w.logger.Debug("Telemetry batch sent successfully", domain.Int("count", len(batch)))
}
