package middleware

import (
	"crypto/subtle"

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
			errors.Respond(c, nil, errors.ErrUnauthorized())
			return
		}

		if subtle.ConstantTimeCompare([]byte(key), []byte(apiKey)) != 1 {
			errors.Respond(c, nil, errors.ErrUnauthorized())
			return
		}

		c.Next()
	}
}
