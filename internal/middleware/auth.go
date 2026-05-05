package middleware

import (
	"net/http"

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
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized access to Admin API",
			})
			return
		}

		c.Next()
	}
}
