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

func (p *Pipeline) snapshotConfig() *config.SecurityConfig {
	p.mu.RLock()
	cfg := p.cfg
	p.mu.RUnlock()
	return cfg
}

func (p *Pipeline) Inspect(req *domain.WafRequest) (domain.Action, []*domain.SecurityEvent) {
	cfg := p.snapshotConfig()
	var totalScore int
	var allEvents []*domain.SecurityEvent
	var mu sync.Mutex

	var fastMatchEvents []*domain.SecurityEvent
	for _, engine := range p.engines {
		if engine.ID() == "fast-match" {
			fastMatchEvents = engine.Evaluate(req)
			break
		}
	}

	if len(fastMatchEvents) > 0 {
		p.exporter.Export(fastMatchEvents...)
		allEvents = append(allEvents, fastMatchEvents...)
		totalScore += p.scorer.CalculateScore(fastMatchEvents)
		if p.scorer.ShouldBlock(totalScore, cfg.BlockThreshold) {
			return domain.ActionBlock, allEvents
		}
	} else if len(req.Body) < 1024 {
		return domain.ActionAllow, nil
	}

	g, gCtx := errgroup.WithContext(context.Background())
	for _, engine := range p.engines {
		if engine.ID() == "fast-match" {
			continue
		}

		e := engine
		g.Go(func() error {
			select {
			case <-gCtx.Done():
				return nil
			default:
			}

			events := e.Evaluate(req)
			if len(events) > 0 {
				p.exporter.Export(events...)
				mu.Lock()
				allEvents = append(allEvents, events...)
				totalScore += p.scorer.CalculateScore(events)
				isBlocking := p.scorer.ShouldBlock(totalScore, cfg.BlockThreshold)
				mu.Unlock()

				if isBlocking {
					return fmt.Errorf("threshold reached")
				}
			}
			return nil
		})
	}
	_ = g.Wait()

	if p.scorer.ShouldBlock(totalScore, cfg.BlockThreshold) {
		p.logger.Warn("Request Blocked",
			domain.String("req_id", req.ID),
			domain.Int("total_score", totalScore),
		)
		return domain.ActionBlock, allEvents
	}

	return domain.ActionAllow, allEvents
}

func (p *Pipeline) InspectResponse(body []byte) (domain.Action, *domain.SecurityEvent, []byte) {
	cfg := p.snapshotConfig()
	if p.dlpEngine == nil || !cfg.Dlp.Enabled {
		return domain.ActionAllow, nil, body
	}

	events := p.dlpEngine.InspectResponse(body)
	if len(events) > 0 {
		p.exporter.Export(events...)

		if cfg.Dlp.Action == "mask" {
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
