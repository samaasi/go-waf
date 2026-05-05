package errors

import (
	"log/slog"
	"os"

	"github.com/gin-gonic/gin"
)

var showHints = os.Getenv("WAF_DEBUG_HINTS") == "true"

func Respond(c *gin.Context, data any, err *AppError) {
	reqID := c.GetString("X-Request-ID")
	
	env := &Envelope{
		Success:   err == nil,
		Data:      data,
		RequestID: reqID,
	}

	if err != nil {
		// Log the error with internal details
		slog.Error("Request failed",
			slog.String("request_id", reqID),
			slog.String("code", err.Code),
			slog.Int("status", err.Status),
			slog.String("path", c.Request.URL.Path),
			slog.String("method", c.Request.Method),
			slog.Any("internal", err.Internal),
		)

		// Strip internal details for client
		clientErr := *err
		clientErr.Internal = nil
		
		if !showHints {
			clientErr.Hint = ""
		}

		env.Error = &clientErr
		c.AbortWithStatusJSON(err.Status, env)
		return
	}

	c.JSON(200, env)
}
