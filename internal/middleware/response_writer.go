package middleware

import (
	"bytes"

	"github.com/gin-gonic/gin"
)

// DlpResponseWriter intercepts the response stream to capture a small buffer
// for Data Loss Prevention (DLP) inspection.
type DlpResponseWriter struct {
	gin.ResponseWriter
	bodyBuffer *bytes.Buffer
	maxSize    int
	status     int
	headerSent bool
}

func NewDlpResponseWriter(w gin.ResponseWriter, maxSize int) *DlpResponseWriter {
	return &DlpResponseWriter{
		ResponseWriter: w,
		bodyBuffer:     bytes.NewBuffer(make([]byte, 0, maxSize)),
		maxSize:        maxSize,
		status:         200,
	}
}

func (w *DlpResponseWriter) WriteHeader(code int) {
	if w.bodyBuffer.Len() >= w.maxSize {
		w.ResponseWriter.WriteHeader(code)
		w.headerSent = true
	}
	w.status = code
}

func (w *DlpResponseWriter) Write(b []byte) (int, error) {
	if w.bodyBuffer.Len() >= w.maxSize || w.headerSent {
		return w.ResponseWriter.Write(b)
	}

	remaining := w.maxSize - w.bodyBuffer.Len()
	if len(b) <= remaining {
		return w.bodyBuffer.Write(b)
	}

	w.bodyBuffer.Write(b[:remaining])

	if !w.headerSent {
		w.ResponseWriter.WriteHeader(w.status)
		w.headerSent = true
	}

	if _, err := w.ResponseWriter.Write(w.bodyBuffer.Bytes()); err != nil {
		return 0, err
	}
	w.bodyBuffer.Reset()

	return w.ResponseWriter.Write(b[remaining:])
}

func (w *DlpResponseWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func (w *DlpResponseWriter) CapturedBody() []byte {
	return w.bodyBuffer.Bytes()
}
