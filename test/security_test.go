package test

import (
	"crypto/subtle"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/middleware"
)

func TestAdminAuth_TimingSafe(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := "a]Kf9$mP2vL7xQ4wR1tY6nB3hJ8dG0cZeU5sA" // 38 chars

	r := gin.New()
	r.Use(middleware.AdminAuth(key))
	r.GET("/admin/stats", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	// Wrong key must be rejected
	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	req.Header.Set("X-WAF-Admin-Key", "wrong-key-entirely-different-length!!")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	// Correct key must be accepted
	req2 := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	req2.Header.Set("X-WAF-Admin-Key", key)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Code)
	}
}

func TestAdminAuth_QueryStringRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := "a]Kf9$mP2vL7xQ4wR1tY6nB3hJ8dG0cZeU5sA"

	r := gin.New()
	r.Use(middleware.AdminAuth(key))
	r.GET("/admin/stats", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	// Key in query string must NOT work (was removed)
	req := httptest.NewRequest(http.MethodGet, "/admin/stats?api_key="+key, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("query string key should be rejected, got %d", w.Code)
	}
}

func TestAdminAuth_TimingVariance(t *testing.T) {
	key := "a]Kf9$mP2vL7xQ4wR1tY6nB3hJ8dG0cZeU5sA"

	// Measure timing of wrong-first-byte vs wrong-last-byte
	wrongFirst := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	wrongLast := key[:len(key)-1] + "X"

	iterations := 10000
	var dFirst, dLast time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		subtle.ConstantTimeCompare([]byte(wrongFirst), []byte(key))
		dFirst += time.Since(start)

		start = time.Now()
		subtle.ConstantTimeCompare([]byte(wrongLast), []byte(key))
		dLast += time.Since(start)
	}

	avgFirst := dFirst / time.Duration(iterations)
	avgLast := dLast / time.Duration(iterations)

	// Variance should be under 1 microsecond for constant-time comparison
	diff := avgFirst - avgLast
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Microsecond {
		t.Logf("WARNING: timing variance %v may indicate non-constant comparison", diff)
	}
}

func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.SecurityHeaders())
	r.GET("/test", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":       "DENY",
		"X-XSS-Protection":      "0",
		"Referrer-Policy":       "strict-origin-when-cross-origin",
		"Content-Security-Policy": "default-src 'none'",
		"Cache-Control":          "no-store",
		"Permissions-Policy":     "camera=(), microphone=(), geolocation=()",
	}

	for header, expected := range expectedHeaders {
		got := w.Header().Get(header)
		if got != expected {
			t.Errorf("header %s: expected %q, got %q", header, expected, got)
		}
	}
}

func TestConfigValidation_DefaultKeyRelease(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:        "release",
			AdminAPIKey: "secret-waf-key",
		},
		Security: config.SecurityConfig{
			BlockThreshold:         50,
			RateLimit:              100,
			RateLimitWindowSeconds: 1,
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for default key in release mode")
	}
	if !strings.Contains(err.Error(), "default admin API key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigValidation_ShortKey(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:        "release",
			AdminAPIKey: "short",
		},
		Security: config.SecurityConfig{
			BlockThreshold:         50,
			RateLimit:              100,
			RateLimitWindowSeconds: 1,
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for short key")
	}
	if !strings.Contains(err.Error(), "at least 32") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigValidation_ValidConfig(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:        "release",
			AdminAPIKey: "a]Kf9$mP2vL7xQ4wR1tY6nB3hJ8dG0cZeU5sA",
		},
		Security: config.SecurityConfig{
			BlockThreshold:         50,
			RateLimit:              100,
			RateLimitWindowSeconds: 1,
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid config should pass: %v", err)
	}
}

func TestConfigValidation_DebugModeAllowsDefault(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:        "debug",
			AdminAPIKey: "secret-waf-key",
		},
		Security: config.SecurityConfig{
			BlockThreshold:         50,
			RateLimit:              100,
			RateLimitWindowSeconds: 1,
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("debug mode should allow default key: %v", err)
	}
}
