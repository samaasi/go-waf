package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/samaasi/go-waf/internal/analysis"
	"github.com/samaasi/go-waf/internal/analysis/engines"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/middleware"
	"github.com/samaasi/go-waf/internal/platform/logger"
	"github.com/samaasi/go-waf/internal/platform/telemetry"
	"github.com/samaasi/go-waf/internal/store"
	"github.com/samaasi/go-waf/internal/worker"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestIPReputationPersistence(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := logger.NewZapAdapter(zap.NewNop())
	cfg := &config.SecurityConfig{
		BlockThreshold: 5,
	}

	// Use MockCollectionStore for testing persistence without real Redis
	mockStore := store.NewMockCollectionStore()
	
	crsEngine := engines.NewCRSLangEngine("../../configs/rules/persistence.yaml", mockStore)
	err := crsEngine.LoadRules()
	assert.NoError(t, err)

	// Setup Audit Logging
	auditLogPath := "test_audit.log"
	os.Remove(auditLogPath)
	defer os.Remove(auditLogPath)
	
	auditWorker := worker.NewAuditWorker(auditLogPath, 100, log)
	go auditWorker.Start(context.Background())
	
	exporter := telemetry.NewLocalAuditExporter(auditWorker.GetQueue())

	pipeline := analysis.NewPipeline(cfg, log, "", exporter, crsEngine)
	mw := middleware.New(pipeline, nil, cfg, &config.ServerConfig{}, nil, log, nil)

	r := gin.New()
	r.Use(mw.Handler())
	r.GET("/trigger", func(c *gin.Context) {
		c.String(http.StatusOK, "Triggered")
	})

	// First request: increments counter
	req1, _ := http.NewRequest("GET", "/trigger", nil)
	req1.RemoteAddr = "1.2.3.4:1234"
	resp1 := httptest.NewRecorder()
	r.ServeHTTP(resp1, req1)
	assert.Equal(t, http.StatusOK, resp1.Code)

	// Second request: increments counter and blocks
	req2, _ := http.NewRequest("GET", "/trigger", nil)
	req2.RemoteAddr = "1.2.3.4:1234"
	resp2 := httptest.NewRecorder()
	r.ServeHTTP(resp2, req2)
	assert.Equal(t, http.StatusForbidden, resp2.Code)

	// Wait for worker to flush
	time.Sleep(100 * time.Millisecond)

	// Verify audit log
	data, err := os.ReadFile(auditLogPath)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "Reputation block")
	assert.Contains(t, string(data), "1.2.3.4")
}
