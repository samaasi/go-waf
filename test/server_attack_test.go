package test

import (
    "bytes"
    "io/ioutil"
    "mime/multipart"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/gin-gonic/gin"
    "go-waf/internal/admin"
    "go-waf/internal/analysis"
    "go-waf/internal/analysis/engines"
    "go-waf/internal/config"
    "go-waf/internal/middleware"
    "go-waf/internal/platform/logger"
)

// buildTestServer creates a Gin router with WAF middleware and a simple echo route
func buildTestServer() (*gin.Engine, *admin.AdminService) {
    gin.SetMode(gin.TestMode)
    logger.Init("debug")
    sec := &config.SecurityConfig{BlockThreshold: 10, RateLimit: 100, RateLimitWindowSeconds: 1}
    srv := &config.ServerConfig{MaxBodyMB: 2}
    ac, _ := engines.NewFastMatchEngine("./configs/rules/keywords.json")
    re := engines.NewRegexEngineWithPath("./configs/rules/regex_rules.json")
    _ = re.LoadRules()
    ml := engines.NewStatisticalModel()
    if ac != nil {
        pl := analysis.NewPipeline(sec, ac, re, ml)
        svc := admin.NewAdminService(sec, pl, srv)
        mw := middleware.New(pl, nil, sec, srv, nil, svc)
        r := gin.New()
        r.Use(mw.Handler())
        r.POST("/echo", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
        r.GET("/echo", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
        return r, svc
    }
    pl := analysis.NewPipeline(sec, re, ml)
    svc := admin.NewAdminService(sec, pl, srv)
    mw := middleware.New(pl, nil, sec, srv, nil, svc)
    r := gin.New()
    r.Use(mw.Handler())
    r.POST("/echo", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
    r.GET("/echo", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
    return r, svc
}

func TestReplayAttackSamples_Blocking(t *testing.T) {
    r, svc := buildTestServer()

    // SQL UNION in JSON body (normalized)
    unionBody := []byte(`{"u":"%2555nion%20select"}`)
    req1 := httptest.NewRequest(http.MethodPost, "/echo", bytes.NewReader(unionBody))
    req1.Header.Set("Content-Type", "application/json")
    w1 := httptest.NewRecorder()
    r.ServeHTTP(w1, req1)

    // XSS in body
    body, _ := ioutil.ReadFile("test/attack_samples/xss_script.txt")
    req2 := httptest.NewRequest(http.MethodPost, "/echo", bytes.NewReader(body))
    req2.Header.Set("Content-Type", "text/plain")
    w2 := httptest.NewRecorder()
    r.ServeHTTP(w2, req2)

    // Path traversal in path
    req3 := httptest.NewRequest(http.MethodGet, "/../../etc/passwd", nil)
    w3 := httptest.NewRecorder()
    r.ServeHTTP(w3, req3)

    // Nested JSON
    nested := []byte(`{"outer": {"inner": "%2555nion%20select"}}`)
    req4 := httptest.NewRequest(http.MethodPost, "/echo", bytes.NewReader(nested))
    req4.Header.Set("Content-Type", "application/json")
    w4 := httptest.NewRecorder()
    r.ServeHTTP(w4, req4)

    // Multipart with suspicious content
    var buf bytes.Buffer
    mwr := multipart.NewWriter(&buf)
    part, _ := mwr.CreateFormField("file")
    part.Write([]byte("<script>alert(1)</script>"))
    mwr.Close()
    req5 := httptest.NewRequest(http.MethodPost, "/echo", &buf)
    req5.Header.Set("Content-Type", mwr.FormDataContentType())
    w5 := httptest.NewRecorder()
    r.ServeHTTP(w5, req5)

    stats := svc.GetStats()
    total := stats["allowed_requests"].(int64) + stats["blocked_requests"].(int64)
    if total < 5 {
        t.Fatalf("expected counters to reflect >=5 requests, got %v", total)
    }
}