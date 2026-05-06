package middleware

import (
	"bytes"
	"net/http"

	"github.com/gin-gonic/gin"
)

// WafResponseWriter intercepts the response stream to capture headers and body
// for Phase 3 (Response Headers) and Phase 4 (Response Body) inspection.
type WafResponseWriter struct {
	gin.ResponseWriter
	bodyBuffer *bytes.Buffer
	maxSize    int
	status     int
	headerSent bool
}

func NewWafResponseWriter(w gin.ResponseWriter, maxSize int) *WafResponseWriter {
	return &WafResponseWriter{
		ResponseWriter: w,
		bodyBuffer:     bytes.NewBuffer(make([]byte, 0, maxSize)),
		maxSize:        maxSize,
		status:         http.StatusOK,
	}
}

func (w *WafResponseWriter) WriteHeader(code int) {
	w.status = code
	// We don't call the underlying WriteHeader yet because WAF Phase 3 might block it
}

func (w *WafResponseWriter) Status() int {
	return w.status
}

func (w *WafResponseWriter) Write(b []byte) (int, error) {
	if w.bodyBuffer.Len() >= w.maxSize || w.headerSent {
		if !w.headerSent {
			w.ResponseWriter.WriteHeader(w.status)
			w.headerSent = true
		}
		return w.ResponseWriter.Write(b)
	}

	remaining := w.maxSize - w.bodyBuffer.Len()
	if len(b) <= remaining {
		return w.bodyBuffer.Write(b)
	}

	// Buffer limit reached, flush existing buffer and continue streaming
	w.bodyBuffer.Write(b[:remaining])
	if err := w.FlushBuffer(); err != nil {
		return 0, err
	}
	return w.ResponseWriter.Write(b[remaining:])
}

func (w *WafResponseWriter) FlushBuffer() error {
	if w.headerSent {
		return nil
	}
	w.ResponseWriter.WriteHeader(w.status)
	w.headerSent = true
	if w.bodyBuffer.Len() > 0 {
		if _, err := w.ResponseWriter.Write(w.bodyBuffer.Bytes()); err != nil {
			return err
		}
		w.bodyBuffer.Reset()
	}
	return nil
}

func (w *WafResponseWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func (w *WafResponseWriter) CapturedBody() []byte {
	return w.bodyBuffer.Bytes()
}
