package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type AdminHandler struct {
	service *AdminService
}

func NewAdminHandler(svc *AdminService) *AdminHandler {
	return &AdminHandler{service: svc}
}

func (h *AdminHandler) RegisterRoutes(r *gin.RouterGroup) {
	admin := r.Group("/admin")
	// In production, add middleware.AuthRequired() here!
	{
		admin.GET("/stats", h.GetStats)
		admin.POST("/config/threshold", h.UpdateThreshold)
	}
}

func (h *AdminHandler) GetStats(c *gin.Context) {
	stats := h.service.GetStats()
	c.JSON(http.StatusOK, stats)
}

type UpdateThresholdReq struct {
	Threshold int `json:"threshold" binding:"required,min=1"`
}

func (h *AdminHandler) UpdateThreshold(c *gin.Context) {
	var req UpdateThresholdReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.service.UpdateBlockThreshold(req.Threshold)
	c.JSON(http.StatusOK, gin.H{"message": "Threshold updated", "new_value": req.Threshold})
}
