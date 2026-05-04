package middleware

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/samaasi/go-waf/internal/analysis"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/internal/platform/cache"
	"github.com/samaasi/go-waf/internal/platform/geoip"
	"github.com/samaasi/go-waf/internal/platform/logger"
	"github.com/samaasi/go-waf/internal/ratelimit"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type WafMiddleware struct {
	pipeline    *analysis.Pipeline
	rateLimiter ratelimit.Limiter
	cfg         *config.SecurityConfig
	serverCfg   *config.ServerConfig
	geo         geoip.GeoIPProvider
	stats       interface {
		IncAllow()
		IncBlock()
	}
}

func New(pipeline *analysis.Pipeline, redis *cache.RedisClient, cfg *config.SecurityConfig, srv *config.ServerConfig, geoProv geoip.GeoIPProvider, stats interface {
	IncAllow()
	IncBlock()
}) *WafMiddleware {
	return &WafMiddleware{
		pipeline:    pipeline,
		rateLimiter: ratelimit.NewRedisLimiter(redis),
		cfg:         cfg,
		serverCfg:   srv,
		geo:         geoProv,
		stats:       stats,
	}
}

func (m *WafMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		reqID := uuid.New().String()

		clientIP := c.ClientIP()
		// Security Hardening: If no trusted proxies are configured, strictly use RemoteAddr to prevent spoofing
		if len(m.serverCfg.TrustedProxies) == 0 {
			if ip, _, err := net.SplitHostPort(c.Request.RemoteAddr); err == nil {
				clientIP = ip
			}
		}

		allowed, remaining, err := m.rateLimiter.Allow(
			c.Request.Context(),
			clientIP+":"+c.Request.URL.Path,
			m.cfg.RateLimit,
			m.cfg.RateLimitWindowSeconds,
		)

		if err != nil {
			logger.Log.Error("Rate Limit check failed", zap.Error(err))
			if !m.cfg.RateLimitFailOpen {
				c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
					"error": "Security service unavailable",
					"code":  "RATE_LIMIT_ERROR",
				})
				return
			}
		} else if !allowed {
			if remaining == -1 {
				logger.Log.Warn("Behavioral Block Active", zap.String("ip", clientIP))
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":  "Access denied due to suspicious behavior",
					"code":   "BEHAVIORAL_BLOCK",
					"req_id": reqID,
				})
				return
			}
			logger.Log.Warn("Rate Limit Exceeded", zap.String("ip", clientIP), zap.String("path", c.Request.URL.Path))
			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", m.cfg.RateLimit))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("Retry-After", fmt.Sprintf("%d", m.cfg.RateLimitWindowSeconds))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests",
				"code":  "RATE_LIMIT_EXCEEDED",
			})
			return
		}

		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

		if m.serverCfg != nil && m.serverCfg.MaxBodyMB > 0 && c.Request.Body != nil {
			maxBytes := int64(m.serverCfg.MaxBodyMB) * 1024 * 1024
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}

		bufferedReq, err := SmartReadBody(c.Request)
		if err != nil {
			logger.Log.Warn("Body read error", zap.Error(err))
			c.AbortWithStatus(http.StatusRequestEntityTooLarge)
			return
		}

		wafReq := &domain.WafRequest{
			ID:        reqID,
			Method:    c.Request.Method,
			Path:      c.Request.URL.Path,
			RemoteIP:  clientIP,
			UserAgent: c.Request.UserAgent(),
			Headers:   c.Request.Header,
			QueryArgs: c.Request.URL.Query(),
			Body:      bufferedReq.Buffer,
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
			_ = m.rateLimiter.ReportViolation(c.Request.Context(), clientIP, violationScore)

			logger.Log.Warn("WAF Blocked Request",
				zap.String("req_id", reqID),
				zap.String("rule", event.RuleName),
				zap.String("ip", clientIP),
				zap.Duration("latency", wafLatency),
				zap.String("matched", event.MatchedData),
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
				logger.Log.Error("DLP Violation Blocked",
					zap.String("req_id", reqID),
					zap.String("rule", resEvent.RuleName),
					zap.String("ip", clientIP),
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
