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
}

func NewPipeline(cfg *config.SecurityConfig, log domain.Logger, dlpRulesPath string, ruleEngines ...domain.RuleEngine) *Pipeline {
	dlp, _ := engines.NewDlpEngine(dlpRulesPath)
	return &Pipeline{
		cfg:       cfg,
		engines:   ruleEngines,
		dlpEngine: dlp,
		logger:    log,
		scorer:    NewScorer(),
	}
}

func (p *Pipeline) Inspect(req *domain.WafRequest) (domain.Action, *domain.SecurityEvent) {
	var totalScore int
	var firstEvent *domain.SecurityEvent
	var mu sync.Mutex

	// 1. Critical/Fast Engines (Negative Model) - Sequential for early exit
	// We assume engines[0] and engines[1] are fast (AC/Regex)
	for i := 0; i < len(p.engines) && i < 2; i++ {
		events := p.engines[i].Evaluate(req)
		if len(events) > 0 {
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

	// 2. Heavy Engines (Positive Model, ML, WASM) - Parallel
	if len(p.engines) > 2 {
		g, gCtx := errgroup.WithContext(context.Background())
		for _, engine := range p.engines[2:] {
			engine := engine
			g.Go(func() error {
				// Check if already blocked by another goroutine
				select {
				case <-gCtx.Done():
					return nil
				default:
				}

				events := engine.Evaluate(req)
				if len(events) > 0 {
					mu.Lock()
					defer mu.Unlock()
					if firstEvent == nil {
						firstEvent = events[0]
					}
					totalScore += p.scorer.CalculateScore(events)
					if p.scorer.ShouldBlock(totalScore, p.cfg.BlockThreshold) {
						// Return error to trigger context cancellation for others
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

// InspectResponse scans outbound response bodies for sensitive data
func (p *Pipeline) InspectResponse(body []byte) (domain.Action, *domain.SecurityEvent) {
	if p.dlpEngine == nil {
		return domain.ActionAllow, nil
	}

	events := p.dlpEngine.InspectResponse(body)
	if len(events) > 0 {
		return domain.ActionBlock, events[0]
	}

	return domain.ActionAllow, nil
}

func (p *Pipeline) CountEngines() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.engines)
}
