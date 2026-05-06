package admin

import (
	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/internal/errors"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type AdminServicer interface {
	GetStats() map[string]interface{}
	IncAllow(method, status string)
	IncBlock(method, status string)
	GetRules() []domain.RuleMetadata
	ToggleRule(id string, enabled bool) bool
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
		admin.GET("/rules", h.ListRules)
		admin.POST("/rules/:id/toggle", h.ToggleRule)
		admin.GET("/metrics", gin.WrapH(promhttp.Handler()))
		admin.GET("/dashboard", h.ServeDashboard)
	}
}

func (h *AdminHandler) GetStats(c *gin.Context) {
	stats := h.service.GetStats()
	errors.Respond(c, stats, nil)
}

func (h *AdminHandler) ListRules(c *gin.Context) {
	rules := h.service.GetRules()
	errors.Respond(c, rules, nil)
}

func (h *AdminHandler) ToggleRule(c *gin.Context) {
	id := c.Param("id")
	var input struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		errors.Respond(c, nil, &errors.AppError{Code: errors.CodeValidation, Message: "Invalid JSON"})
		return
	}

	if h.service.ToggleRule(id, input.Enabled) {
		errors.Respond(c, gin.H{"status": "ok"}, nil)
	} else {
		errors.Respond(c, nil, &errors.AppError{Status: 404, Message: "Rule not found"})
	}
}

func (h *AdminHandler) ServeDashboard(c *gin.Context) {
	c.Header("Content-Type", "text/html")
	c.String(200, dashboardHTML)
}

const dashboardHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>Go-WAF Admin Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }
        .glass { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border-radius: 12px; border: 1px solid rgba(255,255,255,0.1); padding: 20px; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        h1 { color: #38bdf8; margin-top: 0; }
        .stat-val { font-size: 2.5rem; font-weight: bold; color: #38bdf8; }
        .rule-item { display: flex; justify-content: space-between; padding: 10px; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .btn { background: #38bdf8; color: #0f172a; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; }
        .btn-off { background: #ef4444; }
    </style>
</head>
<body>
    <h1>Go-WAF Security Operations</h1>
    <div class="grid">
        <div class="glass">
            <h3>Request Volume</h3>
            <canvas id="trafficChart"></canvas>
        </div>
        <div class="glass">
            <h3>Live Stats</h3>
            <div id="statsContent">Loading...</div>
        </div>
    </div>
    <div class="glass">
        <h3>Active Rule Set</h3>
        <div id="rulesList">Loading...</div>
    </div>

    <script>
        async function fetchStats() {
            const res = await fetch('/admin/stats');
            const data = await res.json();
            const stats = data.data;
            document.getElementById('statsContent').innerHTML = 
                '<div>Allowed: <span class="stat-val">' + stats.allowed_requests + '</span></div>' +
                '<div>Blocked: <span class="stat-val" style="color:#ef4444">' + stats.blocked_requests + '</span></div>' +
                '<div>Engines: ' + stats.engines_count + '</div>' +
                '<div>Uptime: ' + stats.uptime_seconds + 's</div>';
        }

        async function fetchRules() {
            const res = await fetch('/admin/rules');
            const data = await res.json();
            const rules = data.data;
            let html = '';
            rules.forEach(r => {
                const btnClass = r.enabled ? 'btn' : 'btn btn-off';
                html += '<div class="rule-item">' +
                        '<span>[' + r.id + '] ' + r.name + '</span>' +
                        '<button class="' + btnClass + '" onclick="toggleRule(\'' + r.id + '\', ' + !r.enabled + ')">' +
                        (r.enabled ? 'Enabled' : 'Disabled') +
                        '</button>' +
                        '</div>';
            });
            document.getElementById('rulesList').innerHTML = html;
        }

        async function toggleRule(id, enabled) {
            await fetch('/admin/rules/' + id + '/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled })
            });
            fetchRules();
        }

        setInterval(fetchStats, 2000);
        fetchStats();
        fetchRules();
    </script>
</body>
</html>
`
