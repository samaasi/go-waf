package telemetry

import (
	"github.com/samaasi/go-waf/internal/domain"
)

// CloudExporter handles asynchronous event queueing for telemetry.
type CloudExporter struct {
	queue  chan *domain.SecurityEvent
	logger domain.Logger
}

// NewCloudExporter creates a new exporter with a specified buffer size.
func NewCloudExporter(bufferSize int, logger domain.Logger) *CloudExporter {
	return &CloudExporter{
		queue:  make(chan *domain.SecurityEvent, bufferSize),
		logger: logger,
	}
}

// Export pushes events into the background queue.
// It uses a non-blocking select to ensure the WAF request path is never stalled.
func (e *CloudExporter) Export(events ...*domain.SecurityEvent) {
	for _, event := range events {
		select {
		case e.queue <- event:
		default:
			// Queue is full, drop the event to protect WAF performance.
			e.logger.Warn("Telemetry queue full, dropping event",
				domain.String("req_id", event.RequestID),
				domain.String("rule", event.RuleName),
			)
		}
	}
}

// LogTransaction extracts and exports events from the full transaction context.
func (e *CloudExporter) LogTransaction(req *domain.WafRequest, events []*domain.SecurityEvent) {
	if len(events) > 0 {
		e.Export(events...)
	}
}

// GetQueue returns the event channel for the worker to consume.
func (e *CloudExporter) GetQueue() <-chan *domain.SecurityEvent {
	return e.queue
}
