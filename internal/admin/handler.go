package admin

import (
	"github.com/samaasi/go-waf/internal/errors"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type AdminServicer interface {
	GetStats() map[string]interface{}
	UpdateBlockThreshold(newThreshold int)
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
		admin.POST("/config/threshold", h.UpdateThreshold)
		admin.GET("/metrics", gin.WrapH(promhttp.Handler()))
	}
}

func (h *AdminHandler) GetStats(c *gin.Context) {
	stats := h.service.GetStats()
	errors.Respond(c, stats, nil)
}

type UpdateThresholdReq struct {
	Threshold int `json:"threshold" binding:"required,min=1"`
}

func (h *AdminHandler) UpdateThreshold(c *gin.Context) {
	var req UpdateThresholdReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.Respond(c, nil, errors.ErrValidation("threshold", "Invalid threshold value").WithInternal(err))
		return
	}

	h.service.UpdateBlockThreshold(req.Threshold)
	errors.Respond(c, gin.H{"message": "Threshold updated", "new_value": req.Threshold}, nil)
}
