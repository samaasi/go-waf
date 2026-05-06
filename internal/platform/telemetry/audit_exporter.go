package telemetry

import (
	"time"

	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/internal/worker"
)

// LocalAuditExporter bridges rule matches to the persistent audit worker.
type LocalAuditExporter struct {
	queue chan worker.AuditEntry
}

func NewLocalAuditExporter(queue chan worker.AuditEntry) *LocalAuditExporter {
	return &LocalAuditExporter{
		queue: queue,
	}
}

func (e *LocalAuditExporter) Export(events ...*domain.SecurityEvent) {
	if len(events) == 0 {
		return
	}
	// Wrap isolated events in a minimal transaction context for the local log.
	e.LogTransaction(&domain.WafRequest{
		ID: events[0].RequestID,
	}, events)
}

func (e *LocalAuditExporter) LogTransaction(req *domain.WafRequest, events []*domain.SecurityEvent) {
	select {
	case e.queue <- worker.AuditEntry{
		Transaction: req,
		Events:      events,
		Timestamp:   time.Now(),
	}:
	default:
		// Queue full, drop log to protect latency
	}
}
