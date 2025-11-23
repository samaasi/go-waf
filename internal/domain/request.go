package domain

import (
	"net/http"
	"net/url"
)

// Action represents the decision made by the WAF.
type Action string

// WafRequest represents a normalized HTTP request for inspection.
// We extract only what we need to avoid passing heavy framework context objects around.
type WafRequest struct {
	ID        string      `json:"id"`
	Method    string      `json:"method"`
	Path      string      `json:"path"`
	RemoteIP  string      `json:"remote_ip"`
	UserAgent string      `json:"user_agent"`
	Headers   http.Header `json:"headers"`
	QueryArgs url.Values  `json:"query_args"`
	Body      []byte      `json:"body"` // Pre-buffered body
	Protocol  string      `json:"protocol"`
}

const (
	ActionAllow     Action = "ALLOW"
	ActionBlock     Action = "BLOCK"
	ActionLog       Action = "LOG"
	ActionChallenge Action = "CHALLENGE" // e.g., Captcha
)
