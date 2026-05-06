package ftw

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/samaasi/go-waf/internal/analysis"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/internal/middleware"
	"github.com/samaasi/go-waf/internal/platform/logger"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

type mockHeaderEngine struct{}

func (m *mockHeaderEngine) ID() string            { return "mock-header" }
func (m *mockHeaderEngine) Name() string          { return "Mock Header Engine" }
func (m *mockHeaderEngine) LoadRules() error      { return nil }
func (m *mockHeaderEngine) Evaluate(ctx context.Context, req *domain.WafRequest, phase int) []*domain.SecurityEvent {
	if phase == 3 {
		if req.ResponseHeaders.Get("X-Sensitive-Server") != "" {
			return []*domain.SecurityEvent{
				{RuleID: "TEST-PHASE3", RuleName: "Sensitive Header Block", Severity: domain.SeverityCritical},
			}
		}
	}
	return nil
}

func TestResponseInspection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := logger.NewZapAdapter(zap.NewNop())
	cfg := &config.SecurityConfig{
		BlockThreshold: 5, // Low threshold to trigger block
		Dlp: config.DlpConfig{
			Enabled: true,
			Action:  "block",
		},
	}

	headerEngine := &mockHeaderEngine{}
	pipeline := analysis.NewPipeline(cfg, log, "", nil, headerEngine)

	mw := middleware.New(pipeline, nil, cfg, &config.ServerConfig{}, nil, log, nil)

	r := gin.New()
	r.Use(mw.Handler())

	r.GET("/leak", func(c *gin.Context) {
		c.String(http.StatusOK, "Your card is 4111111111111111")
	})

	r.GET("/sensitive-header", func(c *gin.Context) {
		c.Header("X-Sensitive-Server", "Secret-Internal-System")
		c.String(http.StatusOK, "Safe content")
	})

	r.GET("/safe", func(c *gin.Context) {
		c.String(http.StatusOK, "Hello world")
	})

	t.Run("DLP Block (Phase 4)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/leak", nil)
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusForbidden, resp.Code)
		assert.Contains(t, resp.Body.String(), "Security policy violation")
	})

	t.Run("Header Block (Phase 3)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/sensitive-header", nil)
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		if resp.Code != http.StatusForbidden {
			fmt.Printf("Phase 3 Failed: Status=%d Headers=%v Body=%s\n", resp.Code, resp.Header(), resp.Body.String())
		}

		assert.Equal(t, http.StatusForbidden, resp.Code)
		assert.Contains(t, resp.Body.String(), "Security policy violation")
	})

	t.Run("Safe Response", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/safe", nil)
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, "Hello world", resp.Body.String())
	})
}
