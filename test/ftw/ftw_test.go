package ftw

import (
	"net/http"
	"testing"
	"time"
)

func TestSQLInjection(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{"942100: libinjection detection", "/?id=1'%20OR%201=1%20--"},
		{"942140: Common DB Names", "/?table=information_schema.tables"},
		{"942160: Blind SQLi (sleep)", "/?wait=sleep(5)"},
		{"942270: UNION SELECT", "/?q=1%20union%20select%201,2,3"},
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fullURL := "http://localhost:8080" + tt.uri
			req, err := http.NewRequest("GET", fullURL, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("failed to send request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("expected 403 Forbidden, got %d for URI %s", resp.StatusCode, tt.uri)
			}
		})
	}
}
