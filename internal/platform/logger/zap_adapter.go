package logger

import (
	"github.com/samaasi/go-waf/internal/domain"
	"go.uber.org/zap"
)

// ZapAdapter wraps a zap logger to satisfy the domain.Logger interface.
type ZapAdapter struct {
	logger *zap.Logger
}

func NewZapAdapter(l *zap.Logger) *ZapAdapter {
	return &ZapAdapter{logger: l}
}

func (z *ZapAdapter) Debug(msg string, fields ...domain.Field) {
	z.logger.Debug(msg, z.toZapFields(fields)...)
}

func (z *ZapAdapter) Info(msg string, fields ...domain.Field) {
	z.logger.Info(msg, z.toZapFields(fields)...)
}

func (z *ZapAdapter) Warn(msg string, fields ...domain.Field) {
	z.logger.Warn(msg, z.toZapFields(fields)...)
}

func (z *ZapAdapter) Error(msg string, fields ...domain.Field) {
	z.logger.Error(msg, z.toZapFields(fields)...)
}

func (z *ZapAdapter) toZapFields(fields []domain.Field) []zap.Field {
	zf := make([]zap.Field, len(fields))
	for i, f := range fields {
		zf[i] = zap.Any(f.Key, f.Value)
	}
	return zf
}
