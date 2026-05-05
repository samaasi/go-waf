package server

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/samaasi/go-waf/internal/domain"

	"github.com/gin-gonic/gin"
)

// ProxyHandler creates a Gin handler that reverse-proxies requests to an upstream server.
// It also injects security headers and matches if configured.
func ProxyHandler(target string, log domain.Logger) gin.HandlerFunc {
	url, err := url.Parse(target)
	if err != nil {
		panic(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(url)

	// Customize the transport for better performance and error handling
	proxy.Transport = &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Error("Proxy error", domain.String("path", r.URL.Path), domain.Any("error", err))
		w.WriteHeader(http.StatusBadGateway)
	}

	return func(c *gin.Context) {
		// Before proxying, we can inject headers for upstream insights
		// if the WAF logic (which ran in a previous middleware) attached them.
		
		// Set original host header
		c.Request.Header.Set("X-Forwarded-Host", c.Request.Host)
		c.Request.Host = url.Host

		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

// InsightHeadersMiddleware injects WAF match details into request headers 
// so upstream services can use the data.
func InsightHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Run next middleware first to let WAF populate context
		c.Next()

		// If the request is being allowed, we can still attach metadata 
		// about "close calls" or matched non-blocking rules.
		events, exists := c.Get("waf_events")
		if exists {
			evList := events.([]*domain.SecurityEvent)
			if len(evList) > 0 {
				var ids []string
				for _, e := range evList {
					ids = append(ids, e.RuleID)
				}
				c.Request.Header.Set("X-WAF-Match", strings.Join(ids, ","))
			}
		}
	}
}
