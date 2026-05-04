package domain

// Field represents a log metadata field
type Field struct {
	Key   string
	Value interface{}
}

// Logger is the abstraction for logging across the WAF core.
// It allows us to swap zap for any other provider without touching core logic.
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
}

// Helper functions for common fields to keep core code clean
func String(key, value string) Field { return Field{Key: key, Value: value} }
func Int(key string, value int) Field    { return Field{Key: key, Value: value} }
func Any(key string, value interface{}) Field { return Field{Key: key, Value: value} }

// NoopLogger is a logger that does nothing, useful for tests and benchmarks.
type NoopLogger struct{}

func (n *NoopLogger) Debug(msg string, fields ...Field) {}
func (n *NoopLogger) Info(msg string, fields ...Field)  {}
func (n *NoopLogger) Warn(msg string, fields ...Field)  {}
func (n *NoopLogger) Error(msg string, fields ...Field) {}
