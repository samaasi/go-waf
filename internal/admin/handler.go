package admin

import (
	"github.com/samaasi/go-waf/internal/errors"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type AdminServicer interface {
	GetStats() map[string]interface{}
	IncAllow(method, status string)
	IncBlock(method, status string)
}

type AdminHandler struct {
	service AdminServicer
}

func NewAdminHandler(svc AdminServicer) *AdminHandler {
	return &AdminHandler{service: svc}
}

func (h *AdminHandler) RegisterRoutes(r *gin.RouterGroup) {
	admin := r.Group("/admin")
	{
		admin.GET("/stats", h.GetStats)
		admin.GET("/metrics", gin.WrapH(promhttp.Handler()))
	}
}

func (h *AdminHandler) GetStats(c *gin.Context) {
	stats := h.service.GetStats()
	errors.Respond(c, stats, nil)
}
