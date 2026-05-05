package middleware

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/samaasi/go-waf/internal/analysis"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/internal/ratelimit"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

type WafMiddleware struct {
	pipeline    *analysis.Pipeline
	rateLimiter ratelimit.Limiter
	cfg         *config.SecurityConfig
	serverCfg   *config.ServerConfig
	geo         domain.GeoIPProvider
	logger      domain.Logger
	stats       interface {
		IncAllow()
		IncBlock()
	}
}

func New(pipeline *analysis.Pipeline, limiter ratelimit.Limiter, cfg *config.SecurityConfig, srv *config.ServerConfig, geoProv domain.GeoIPProvider, log domain.Logger, stats interface {
	IncAllow()
	IncBlock()
}) *WafMiddleware {
	return &WafMiddleware{
		pipeline:    pipeline,
		rateLimiter: limiter,
		cfg:         cfg,
		serverCfg:   srv,
		geo:         geoProv,
		logger:      log,
		stats:       stats,
	}
}

func (m *WafMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		reqID := uuid.New().String()

		clientIP := c.ClientIP()
		if len(m.serverCfg.TrustedProxies) == 0 {
			if ip, _, err := net.SplitHostPort(c.Request.RemoteAddr); err == nil {
				clientIP = ip
			}
		}

		// Rate limiting is optional — skip if no limiter is configured
		var remaining int64
		if m.rateLimiter != nil {
			allowed, rem, err := m.rateLimiter.Allow(
				c.Request.Context(),
				clientIP+":"+c.Request.URL.Path,
				m.cfg.RateLimit,
				m.cfg.RateLimitWindowSeconds,
			)
			remaining = rem

			if err != nil {
				m.logger.Error("Rate Limit check failed", domain.Any("error", err))
				if !m.cfg.RateLimitFailOpen {
					c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
						"error": "Security service unavailable",
						"code":  "RATE_LIMIT_ERROR",
					})
					return
				}
			} else if !allowed {
				if remaining == -1 {
					m.logger.Warn("Behavioral Block Active", domain.String("ip", clientIP))
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
						"error":  "Access denied due to suspicious behavior",
						"code":   "BEHAVIORAL_BLOCK",
						"req_id": reqID,
					})
					return
				}
				m.logger.Warn("Rate Limit Exceeded", domain.String("ip", clientIP), domain.String("path", c.Request.URL.Path))
				c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", m.cfg.RateLimit))
				c.Header("X-RateLimit-Remaining", "0")
				c.Header("Retry-After", fmt.Sprintf("%d", m.cfg.RateLimitWindowSeconds))
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
					"error": "Too many requests",
					"code":  "RATE_LIMIT_EXCEEDED",
				})
				return
			}
		}

		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

		if m.serverCfg != nil && m.serverCfg.MaxBodyMB > 0 && c.Request.Body != nil {
			maxBytes := int64(m.serverCfg.MaxBodyMB) * 1024 * 1024
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}

		// Use buffer pool for body reading
		buf := bufferPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufferPool.Put(buf)

		if c.Request.Body != nil {
			_, _ = io.Copy(buf, c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
		}

		wafReq := &domain.WafRequest{
			ID:        reqID,
			Method:    c.Request.Method,
			Path:      c.Request.URL.Path,
			RemoteIP:  clientIP,
			UserAgent: c.Request.UserAgent(),
			Headers:   c.Request.Header,
			QueryArgs: c.Request.URL.Query(),
			Body:      buf.Bytes(),
			Protocol:  c.Request.Proto,
		}

		if m.cfg.EnableGeoIP && m.geo != nil {
			if country, err := m.geo.GetCountry(clientIP); err == nil {
				for _, b := range m.cfg.BlockCountries {
					if country == b {
						c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Access denied", "code": "GEO_BLOCKED"})
						return
					}
				}
				if len(m.cfg.AllowCountries) > 0 {
					allowed := false
					for _, a := range m.cfg.AllowCountries {
						if country == a {
							allowed = true
							break
						}
					}
					if !allowed {
						c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Access denied", "code": "GEO_NOT_ALLOWED"})
						return
					}
				}
			}
		}

		verdict, event := m.pipeline.Inspect(wafReq)

		// Log the latency of the WAF itself
		wafLatency := time.Since(start)

		if verdict == domain.ActionBlock {
			// Behavioral Escalation: Report this violation to the threat scorer
			violationScore := 10
			if event.Severity == domain.SeverityCritical {
				violationScore = 50
			}
			if m.rateLimiter != nil {
				_ = m.rateLimiter.ReportViolation(c.Request.Context(), clientIP, violationScore)
			}

			m.logger.Warn("WAF Blocked Request",
				domain.String("req_id", reqID),
				domain.String("rule", event.RuleName),
				domain.String("ip", clientIP),
				domain.Any("latency", wafLatency),
				domain.String("matched", event.MatchedData),
			)
			if m.stats != nil {
				m.stats.IncBlock()
			}

			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":      "Request blocked by WAF",
				"request_id": reqID,
				"reason":     "Security Violation",
			})
			return
		}

		if m.stats != nil {
			m.stats.IncAllow()
		}
		// Add metadata for the downstream application
		c.Set("X-WAF-Latency", wafLatency)
		c.Set("X-Request-ID", reqID)
		c.Writer.Header().Set("X-Request-ID", reqID)

		// DLP: Wrap the writer to capture response body
		dlpWriter := NewDlpResponseWriter(c.Writer, 8*1024)
		c.Writer = dlpWriter

		c.Next()

		// Post-request DLP inspection (Gated Buffer Mode)
		if dlpWriter.bodyBuffer.Len() > 0 {
			resVerdict, resEvent := m.pipeline.InspectResponse(dlpWriter.CapturedBody())

			if resVerdict == domain.ActionBlock {
				m.logger.Error("DLP Violation Blocked",
					domain.String("req_id", reqID),
					domain.String("rule", resEvent.RuleName),
					domain.String("ip", clientIP),
				)

				// Critical: Clear the gated buffer and override with 403
				dlpWriter.bodyBuffer.Reset()
				dlpWriter.ResponseWriter.WriteHeader(http.StatusForbidden)
				_, _ = dlpWriter.ResponseWriter.Write([]byte(`{"error": "Sensitive data leak prevented", "code": "DLP_BLOCK"}`))
			} else {
				if !dlpWriter.headerSent {
					dlpWriter.ResponseWriter.WriteHeader(dlpWriter.status)
				}
				_, _ = dlpWriter.ResponseWriter.Write(dlpWriter.CapturedBody())
			}
		}
	}
}
