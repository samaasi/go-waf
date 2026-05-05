package worker

import (
	"context"
	"os"

	"github.com/samaasi/go-waf/internal/analysis"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/internal/platform/k8s"
)

type K8sOperatorWorker struct {
	pipeline *analysis.Pipeline
	logger   domain.Logger
}

func NewK8sOperatorWorker(pipeline *analysis.Pipeline, logger domain.Logger) *K8sOperatorWorker {
	return &K8sOperatorWorker{
		pipeline: pipeline,
		logger:   logger,
	}
}

func (w *K8sOperatorWorker) Start(ctx context.Context) error {
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		w.logger.Debug("K8s environment not detected, skipping K8sOperatorWorker")
		return nil
	}

	watcher, err := k8s.NewPolicyWatcher(w.logger, w.applyPolicy)
	if err != nil {
		w.logger.Error("Failed to initialize K8s policy watcher", domain.Any("error", err))
		return err
	}

	go watcher.Start(ctx)

	w.logger.Info("K8sOperatorWorker successfully hooked into cluster events")
	<-ctx.Done()
	return nil
}

func (w *K8sOperatorWorker) applyPolicy(policy *k8s.WafPolicy) {
	w.logger.Info("Applying new WAF policy from K8s", domain.String("policy", policy.Name))

	// Map K8s CRD spec to our internal SecurityConfig
	newCfg := &config.SecurityConfig{
		BlockThreshold:         policy.Spec.BlockThreshold,
		EnableBotShield:        policy.Spec.EnableBotShield,
		BlockCountries:         policy.Spec.BlockCountries,
		AllowCountries:         policy.Spec.AllowCountries,
		EnableGeoIP:            true,
		EnableSchemaValidation: true,
	}

	// Map DLP settings
	newCfg.Dlp.Enabled = policy.Spec.Dlp.Enabled
	newCfg.Dlp.Action = policy.Spec.Dlp.Action

	// Trigger hot-reload in the analysis pipeline
	w.pipeline.UpdateConfig(newCfg)
}
