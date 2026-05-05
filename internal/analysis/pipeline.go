package analysis

import (
	"context"
	"fmt"
	"sync"

	"github.com/samaasi/go-waf/internal/analysis/engines"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"

	"golang.org/x/sync/errgroup"
)

type Pipeline struct {
	cfg       *config.SecurityConfig
	engines   []domain.RuleEngine
	dlpEngine *engines.DlpEngine
	logger    domain.Logger
	mu        sync.RWMutex
	scorer    *Scorer
	exporter  domain.AuditExporter
}

func NewPipeline(cfg *config.SecurityConfig, log domain.Logger, dlpRulesPath string, exporter domain.AuditExporter, ruleEngines ...domain.RuleEngine) *Pipeline {
	dlp, _ := engines.NewDlpEngine(dlpRulesPath)
	if exporter == nil {
		exporter = &domain.NoopAuditExporter{}
	}
	return &Pipeline{
		cfg:       cfg,
		engines:   ruleEngines,
		dlpEngine: dlp,
		logger:    log,
		scorer:    NewScorer(),
		exporter:  exporter,
	}
}

func (p *Pipeline) Inspect(req *domain.WafRequest) (domain.Action, *domain.SecurityEvent) {
	var totalScore int
	var firstEvent *domain.SecurityEvent
	var mu sync.Mutex

	for i := 0; i < len(p.engines) && i < 2; i++ {
		events := p.engines[i].Evaluate(req)
		if len(events) > 0 {
			p.exporter.Export(events...)
			if firstEvent == nil {
				firstEvent = events[0]
			}
			score := p.scorer.CalculateScore(events)
			totalScore += score
			if p.scorer.ShouldBlock(totalScore, p.cfg.BlockThreshold) {
				return domain.ActionBlock, firstEvent
			}
		}
	}

	if len(p.engines) > 2 {
		g, gCtx := errgroup.WithContext(context.Background())
		for _, engine := range p.engines[2:] {
			g.Go(func() error {
				select {
				case <-gCtx.Done():
					return nil
				default:
				}

				events := engine.Evaluate(req)
				if len(events) > 0 {
					p.exporter.Export(events...)
					mu.Lock()
					defer mu.Unlock()
					if firstEvent == nil {
						firstEvent = events[0]
					}
					totalScore += p.scorer.CalculateScore(events)
					if p.scorer.ShouldBlock(totalScore, p.cfg.BlockThreshold) {
						return fmt.Errorf("threshold reached")
					}
				}
				return nil
			})
		}
		_ = g.Wait()
	}

	if p.scorer.ShouldBlock(totalScore, p.cfg.BlockThreshold) {
		p.logger.Warn("Request Blocked",
			domain.String("req_id", req.ID),
			domain.Int("total_score", totalScore),
		)
		return domain.ActionBlock, firstEvent
	}

	return domain.ActionAllow, nil
}

func (p *Pipeline) InspectResponse(body []byte) (domain.Action, *domain.SecurityEvent, []byte) {
	if p.dlpEngine == nil || !p.cfg.Dlp.Enabled {
		return domain.ActionAllow, nil, body
	}

	events := p.dlpEngine.InspectResponse(body)
	if len(events) > 0 {
		p.exporter.Export(events...)

		if p.cfg.Dlp.Action == "mask" {
			maskedBody := p.dlpEngine.Mask(body)
			return domain.ActionAllow, events[0], maskedBody
		}

		return domain.ActionBlock, events[0], body
	}

	return domain.ActionAllow, nil, body
}

func (p *Pipeline) UpdateConfig(newCfg *config.SecurityConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = newCfg
	p.logger.Info("Security configuration updated dynamically")
}

func (p *Pipeline) CountEngines() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.engines)
}
