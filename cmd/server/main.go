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
	tlsutil "github.com/samaasi/go-waf/internal/platform/tls"
	"github.com/samaasi/go-waf/internal/server"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/sync/errgroup"
)

func main() {
	cfg, err := config.LoadConfig(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Config validation failed: %v\n", err)
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

	h2s := &http2.Server{}
	srv := &http.Server{
		Addr:           fmt.Sprintf(":%s", cfg.Server.Port),
		Handler:        h2c.NewHandler(router, h2s),
		ReadTimeout:    time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:    time.Duration(cfg.Server.IdleTimeout) * time.Second,
		MaxHeaderBytes: cfg.Server.MaxHeaderBytes,
	}

	if cfg.TLS.Enabled {
		tlsCfg, err := tlsutil.BuildTLSConfig(&cfg.TLS)
		if err != nil {
			log.Error("Failed to build TLS config", domain.Any("error", err))
			os.Exit(1)
		}
		srv.TLSConfig = tlsCfg
	}

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if cfg.TLS.Enabled {
			log.Info("HTTPS server listening", domain.String("addr", srv.Addr))
			if err := srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("https server: %w", err)
			}
		} else {
			log.Info("HTTP server listening (TLS disabled)", domain.String("addr", srv.Addr))
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("http server: %w", err)
			}
		}
		return nil
	})

	g.Go(func() error {
		<-gCtx.Done()
		log.Info("Draining in-flight requests...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		return srv.Shutdown(shutdownCtx)
	})

	for _, w := range application.Workers {
		w := w
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
