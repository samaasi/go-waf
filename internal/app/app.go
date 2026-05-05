package app

import (
	"github.com/samaasi/go-waf/internal/admin"
	"github.com/samaasi/go-waf/internal/analysis"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/internal/middleware"
	"github.com/samaasi/go-waf/internal/store"
	"github.com/samaasi/go-waf/internal/worker"
)

type App struct {
	Config       *config.Config
	Logger       domain.Logger
	Redis        *store.RedisClient
	Pipeline     *analysis.Pipeline
	AdminSvc     *admin.AdminService
	WAF          *middleware.WafMiddleware
	AdminHandler *admin.AdminHandler
	Workers      []worker.Worker
	Cleanup      func()
}
