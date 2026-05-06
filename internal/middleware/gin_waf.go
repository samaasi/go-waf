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
	"github.com/samaasi/go-waf/internal/errors"
	"github.com/samaasi/go-waf/internal/ratelimit"
	"github.com/samaasi/go-waf/pkg/utils"

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
	metrics     domain.Metrics
	ipChecker   *utils.IPChecker
}

func New(pipeline *analysis.Pipeline, limiter ratelimit.Limiter, cfg *config.SecurityConfig, srv *config.ServerConfig, geoProv domain.GeoIPProvider, log domain.Logger, metrics domain.Metrics) *WafMiddleware {
	mw := &WafMiddleware{
		pipeline:    pipeline,
		rateLimiter: limiter,
		cfg:         cfg,
		serverCfg:   srv,
		geo:         geoProv,
		logger:      log,
		metrics:     metrics,
	}

	// Build IP checker from config
	if len(cfg.IPAllowlist) > 0 || len(cfg.IPBlocklist) > 0 {
		checker := utils.NewIPChecker()
		for _, ip := range cfg.IPBlocklist {
			_ = checker.Add(ip)
		}
		mw.ipChecker = checker
	}

	return mw
}

func (m *WafMiddleware) GetLogger() domain.Logger {
	return m.logger
}

func (m *WafMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Accept inbound request ID from upstream LB, or generate one
		reqID := c.GetHeader("X-Request-ID")
		if reqID == "" || len(reqID) > 128 {
			reqID = uuid.New().String()
		}

		clientIP := c.ClientIP()
		if len(m.serverCfg.TrustedProxies) == 0 {
			if ip, _, err := net.SplitHostPort(c.Request.RemoteAddr); err == nil {
				clientIP = ip
			}
		}

		// IP Blocklist — immediate rejection, no further processing
		if m.ipChecker != nil && m.ipChecker.IsBlocked(clientIP) {
			m.logger.Warn("IP Blocklist Rejected", domain.String("ip", clientIP))
			if m.metrics != nil {
				m.metrics.IncBlock(c.Request.Method, "403")
			}
			errors.Respond(c, nil, &errors.AppError{
				Code:    errors.CodeSecurity,
				Status:  http.StatusForbidden,
				Message: "Access denied",
			})
			return
		}

		// IP Allowlist — bypass WAF inspection entirely
		if len(m.cfg.IPAllowlist) > 0 {
			allowed := false
			for _, ip := range m.cfg.IPAllowlist {
				if ip == clientIP {
					allowed = true
					break
				}
			}
			if allowed {
				c.Set("X-Request-ID", reqID)
				c.Writer.Header().Set("X-Request-ID", reqID)
				c.Next()
				return
			}
		}

		var remaining int64
		if m.rateLimiter != nil {
			rateLimitKey := clientIP
			if m.cfg.RateLimitKeyStrategy == "per_ip_path" {
				rateLimitKey = clientIP + ":" + c.Request.URL.Path
			}

			allowed, rem, err := m.rateLimiter.Allow(
				c.Request.Context(),
				rateLimitKey,
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

		buf := bufferPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufferPool.Put(buf)

		if c.Request.Body != nil {
			_, _ = io.Copy(buf, c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
		}

		sessionID := ""
		if cookie, err := c.Cookie("session_id"); err == nil {
			sessionID = cookie
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
			SessionID: sessionID,
			TX:        make(map[string]interface{}),
		}

		verdict, events := m.pipeline.Inspect(c.Request.Context(), wafReq)
		allEvents := append([]*domain.SecurityEvent{}, events...)

		wafLatency := time.Since(start)

		if verdict == domain.ActionBlock {
			firstEvent := events[0]
			violationScore := 10
			if firstEvent.Severity == domain.SeverityCritical {
				violationScore = 50
			}
			if m.rateLimiter != nil {
				_ = m.rateLimiter.ReportViolation(c.Request.Context(), clientIP, violationScore)
			}

			m.logger.Warn("WAF Blocked Request",
				domain.String("req_id", reqID),
				domain.String("rule", firstEvent.RuleName),
				domain.String("ip", clientIP),
				domain.Any("latency", wafLatency),
				domain.String("matched", firstEvent.MatchedData),
			)
			if m.metrics != nil {
				m.metrics.IncBlock(c.Request.Method, "403")
				m.metrics.RecordRuleMatch(firstEvent.RuleID, firstEvent.RuleName, firstEvent.Severity.String())
			}

			m.pipeline.FinishTransaction(wafReq, allEvents)

			errors.Respond(c, nil, &errors.AppError{
				Code:    errors.CodeSecurity,
				Status:  http.StatusForbidden,
				Message: "Request blocked by security policy",
				Hint:    "Contact support if you believe this is an error",
			})
			return
		}

		if m.metrics != nil {
			m.metrics.IncAllow(c.Request.Method, "200")
			m.metrics.ObserveLatency(c.Request.Method, wafLatency.Seconds())
		}
		c.Set("X-WAF-Latency", wafLatency)
		c.Set("X-Request-ID", reqID)
		c.Set("waf_events", events)
		c.Writer.Header().Set("X-Request-ID", reqID)

		wafWriter := NewWafResponseWriter(c.Writer, 1024*1024)
		c.Writer = wafWriter

		c.Next()

		wafReq.ResponseStatus = wafWriter.Status()
		wafReq.ResponseHeaders = wafWriter.Header()

		resVerdict3, resEvents3, _ := m.pipeline.InspectResponse(c.Request.Context(), wafReq, 3)
		allEvents = append(allEvents, resEvents3...)
		if resVerdict3 == domain.ActionBlock {
			m.logger.Warn("Phase 3 Block (Response Headers)", domain.String("req_id", reqID))
			m.pipeline.FinishTransaction(wafReq, allEvents)
			wafWriter.bodyBuffer.Reset()
			wafWriter.ResponseWriter.WriteHeader(http.StatusForbidden)
			envelope := fmt.Sprintf(`{"success":false,"error":{"code":"%s","message":"Security policy violation in response headers"},"request_id":"%s"}`, errors.CodeSecurity, reqID)
			_, _ = wafWriter.ResponseWriter.Write([]byte(envelope))
			return
		}

		if wafWriter.bodyBuffer.Len() > 0 {
			wafReq.ResponseBody = wafWriter.CapturedBody()
			resVerdict4, resEvents4, finalBody := m.pipeline.InspectResponse(c.Request.Context(), wafReq, 4)
			allEvents = append(allEvents, resEvents4...)

			if resVerdict4 == domain.ActionBlock {
				firstEvent := resEvents4[0]
				m.logger.Error("Phase 4 Block (Response Body / DLP)",
					domain.String("req_id", reqID),
					domain.String("rule", firstEvent.RuleName),
					domain.String("ip", clientIP),
				)

				m.pipeline.FinishTransaction(wafReq, allEvents)
				wafWriter.bodyBuffer.Reset()
				wafWriter.ResponseWriter.WriteHeader(http.StatusForbidden)
				envelope := fmt.Sprintf(`{"success":false,"error":{"code":"%s","message":"Security policy violation in response"},"request_id":"%s"}`, errors.CodeSecurity, reqID)
				_, _ = wafWriter.ResponseWriter.Write([]byte(envelope))
			} else {
				if resEvents4 != nil && m.cfg.Dlp.Action == "mask" {
					m.logger.Info("DLP Masking Applied", domain.String("req_id", reqID))
				}
				m.pipeline.FinishTransaction(wafReq, allEvents)
				wafWriter.bodyBuffer.Reset()
				_, _ = wafWriter.bodyBuffer.Write(finalBody)
				_ = wafWriter.FlushBuffer()
			}
		} else {
			m.pipeline.FinishTransaction(wafReq, allEvents)
			_ = wafWriter.FlushBuffer()
		}
	}
}
