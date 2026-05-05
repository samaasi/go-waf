package middleware

import (
	"github.com/samaasi/go-waf/internal/errors"

	"github.com/gin-gonic/gin"
)

func AdminAuth(apiKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if apiKey == "" {
			c.Next()
			return
		}

		key := c.GetHeader("X-WAF-Admin-Key")
		if key == "" {
			key = c.Query("api_key")
		}

		if key != apiKey {
			errors.Respond(c, nil, errors.ErrUnauthorized())
			return
		}

		c.Next()
	}
}
