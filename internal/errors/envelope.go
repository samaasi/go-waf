package errors

type Envelope struct {
	Success   bool           `json:"success"`
	Data      any            `json:"data,omitempty"`
	Error     *AppError      `json:"error,omitempty"`
	Meta      map[string]any `json:"meta,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
}

func NewResponse(data any) *Envelope {
	return &Envelope{
		Success: true,
		Data:    data,
	}
}

func (e *Envelope) WithMeta(key string, val any) *Envelope {
	if e.Meta == nil {
		e.Meta = make(map[string]any)
	}
	e.Meta[key] = val
	return e
}
