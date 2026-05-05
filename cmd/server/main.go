package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/samaasi/go-waf/internal/app"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/internal/platform/logger"
	"github.com/samaasi/go-waf/internal/server"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"
)

func main() {
	cfg, err := config.LoadConfig(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	zapLogger := logger.Init(cfg.Log.Level)
	defer zapLogger.Sync()
	log := logger.NewZapAdapter(zapLogger)

	log.Info("Starting WAF Server...")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	application, err := app.Wire(ctx, cfg, log)
	if err != nil {
		log.Error("Failed to wire application", domain.Any("error", err))
		os.Exit(1)
	}
	defer application.Cleanup()

	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := server.NewRouter(application.WAF, application.AdminHandler, &cfg.Server)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
	}

	g, gCtx := errgroup.WithContext(ctx)

	// HTTP Server goroutine
	g.Go(func() error {
		log.Info("HTTP server listening", domain.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	})

	// Graceful shutdown goroutine
	g.Go(func() error {
		<-gCtx.Done()
		log.Info("Draining in-flight requests...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		return srv.Shutdown(shutdownCtx)
	})

	// Worker goroutines
	for _, w := range application.Workers {
		w := w // capture loop variable
		g.Go(func() error {
			return w.Start(gCtx)
		})
	}

	if err := g.Wait(); err != nil {
		log.Error("Server exited with error", domain.Any("error", err))
		os.Exit(1)
	}

	log.Info("Server shutdown complete")
}
