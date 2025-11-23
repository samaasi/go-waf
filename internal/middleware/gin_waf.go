package middleware

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"go-waf/internal/analysis"
	"go-waf/internal/config"
	"go-waf/internal/domain"
	"go-waf/internal/platform/cache"
	"go-waf/internal/platform/logger"
	"go-waf/internal/ratelimit"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type WafMiddleware struct {
	pipeline    *analysis.Pipeline
	rateLimiter ratelimit.Limiter
	cfg         *config.SecurityConfig
}

func New(pipeline *analysis.Pipeline, redis *cache.RedisClient, cfg *config.SecurityConfig) *WafMiddleware {
	return &WafMiddleware{
		pipeline:    pipeline,
		rateLimiter: ratelimit.NewRedisLimiter(redis),
		cfg:         cfg,
	}
}

func (m *WafMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		reqID := uuid.New().String()
		clientIP := c.ClientIP()
		allowed, remaining, err := m.rateLimiter.Allow(
			c.Request.Context(),
			clientIP,
			m.cfg.RateLimit,
			1,
		)

		if err != nil {
			logger.Log.Error("Rate Limit check failed", zap.Error(err))
		} else if !allowed {
			logger.Log.Warn("Rate Limit Exceeded", zap.String("ip", clientIP))
			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", m.cfg.RateLimit))
			c.Header("X-RateLimit-Remaining", "0")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests",
				"code":  "RATE_LIMIT_EXCEEDED",
			})
			return
		}

		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		wafReq := &domain.WafRequest{
			ID:        reqID,
			Method:    c.Request.Method,
			Path:      c.Request.URL.Path,
			RemoteIP:  clientIP,
			UserAgent: c.Request.UserAgent(),
			Headers:   c.Request.Header,
			QueryArgs: c.Request.URL.Query(),
			Body:      bodyBytes,
			Protocol:  c.Request.Proto,
		}

		verdict, event := m.pipeline.Inspect(wafReq)

		// Log the latency of the WAF itself
		wafLatency := time.Since(start)

		if verdict == domain.ActionBlock {
			logger.Log.Warn("WAF Blocked Request",
				zap.String("req_id", reqID),
				zap.String("rule", event.RuleName),
				zap.String("ip", clientIP),
				zap.Duration("latency", wafLatency),
			)

			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":      "Request blocked by WAF",
				"request_id": reqID,
				"reason":     "Security Violation",
			})
			return
		}

		// Add metadata for the downstream application
		c.Set("X-WAF-Latency", wafLatency)
		c.Set("X-Request-ID", reqID)

		c.Next()
	}
}
