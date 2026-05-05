package analysis

import (
	"sync"

	"github.com/samaasi/go-waf/internal/analysis/engines"
	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"
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

// Inspect runs the request through all registered engines
func (p *Pipeline) Inspect(req *domain.WafRequest) (domain.Action, *domain.SecurityEvent) {
	var totalScore int
	var firstEvent *domain.SecurityEvent

	for _, engine := range p.engines {
		events := engine.Evaluate(req)
		if len(events) > 0 && firstEvent == nil {
			firstEvent = events[0]
		}
		totalScore += p.scorer.CalculateScore(events)
		for _, event := range events {
			p.logger.Debug("Rule Matched",
				domain.String("rule", event.RuleName),
				domain.Int("severity", int(event.Severity)),
			)
		}
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
