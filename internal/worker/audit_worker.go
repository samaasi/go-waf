package worker

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/samaasi/go-waf/internal/domain"
)

type AuditEntry struct {
	Transaction *domain.WafRequest      `json:"transaction"`
	Events      []*domain.SecurityEvent `json:"events"`
	Timestamp   time.Time               `json:"timestamp"`
}

type AuditWorker struct {
	queue   chan AuditEntry
	logPath string
	logger  domain.Logger
}

func NewAuditWorker(logPath string, queueSize int, logger domain.Logger) *AuditWorker {
	return &AuditWorker{
		queue:   make(chan AuditEntry, queueSize),
		logPath: logPath,
		logger:  logger,
	}
}

func (w *AuditWorker) GetQueue() chan AuditEntry {
	return w.queue
}

func (w *AuditWorker) Start(ctx context.Context) error {
	f, err := os.OpenFile(w.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	w.logger.Info("Audit worker started", domain.String("path", w.logPath))

	lastRotate := time.Now().Format("2006-01-02")
	
	for {
		select {
		case <-ctx.Done():
			return nil
		case entry := <-w.queue:
			// Daily Rotation Check
			currentDate := time.Now().Format("2006-01-02")
			if currentDate != lastRotate {
				f.Close()
				oldPath := w.logPath + "." + lastRotate
				_ = os.Rename(w.logPath, oldPath)
				
				f, err = os.OpenFile(w.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					w.logger.Error("Failed to rotate audit log", domain.Any("error", err))
					return err
				}
				lastRotate = currentDate
			}

			data, err := json.Marshal(entry)
			if err != nil {
				w.logger.Error("Failed to marshal audit entry", domain.Any("error", err))
				continue
			}
			if _, err := f.Write(append(data, '\n')); err != nil {
				w.logger.Error("Failed to write to audit log", domain.Any("error", err))
			}
		}
	}
}
