package telemetry

import (
	"github.com/samaasi/go-waf/internal/domain"
)

// MultiExporter broadcasts events and transactions to multiple exporters.
type MultiExporter struct {
	exporters []domain.AuditExporter
}

func NewMultiExporter(exporters ...domain.AuditExporter) *MultiExporter {
	return &MultiExporter{
		exporters: exporters,
	}
}

func (m *MultiExporter) Export(events ...*domain.SecurityEvent) {
	for _, e := range m.exporters {
		e.Export(events...)
	}
}

func (m *MultiExporter) LogTransaction(req *domain.WafRequest, events []*domain.SecurityEvent) {
	for _, e := range m.exporters {
		e.LogTransaction(req, events)
	}
}
