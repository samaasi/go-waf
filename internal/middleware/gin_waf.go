package middleware

import (
    "fmt"
    "net/http"
    "time"

    "go-waf/internal/analysis"
    "go-waf/internal/config"
    "go-waf/internal/domain"
    "go-waf/internal/platform/cache"
    "go-waf/internal/platform/geoip"
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
    serverCfg   *config.ServerConfig
    geo         geoip.GeoIPProvider
    stats       interface{ IncAllow(); IncBlock() }
}

func New(pipeline *analysis.Pipeline, redis *cache.RedisClient, cfg *config.SecurityConfig, srv *config.ServerConfig, geoProv geoip.GeoIPProvider, stats interface{ IncAllow(); IncBlock() }) *WafMiddleware {
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
        allowed, remaining, err := m.rateLimiter.Allow(
            c.Request.Context(),
            clientIP+":"+c.Request.URL.Path,
            m.cfg.RateLimit,
            m.cfg.RateLimitWindowSeconds,
        )

		if err != nil {
			logger.Log.Error("Rate Limit check failed", zap.Error(err))
		} else if !allowed {
			logger.Log.Warn("Rate Limit Exceeded", zap.String("ip", clientIP))
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
                        if country == a { allowed = true; break }
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
            logger.Log.Warn("WAF Blocked Request",
                zap.String("req_id", reqID),
                zap.String("rule", event.RuleName),
                zap.String("ip", clientIP),
                zap.Duration("latency", wafLatency),
                zap.String("matched", event.MatchedData),
            )
            if m.stats != nil { m.stats.IncBlock() }

            c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
                "error":      "Request blocked by WAF",
                "request_id": reqID,
                "reason":     "Security Violation",
            })
            return
        }

        if m.stats != nil { m.stats.IncAllow() }
        // Add metadata for the downstream application
        c.Set("X-WAF-Latency", wafLatency)
        c.Set("X-Request-ID", reqID)
        c.Writer.Header().Set("X-Request-ID", reqID)

        c.Next()
	}
}
