package analysis

import (
	"sync"

	"go-waf/internal/analysis/engines"
	"go-waf/internal/config"
	"go-waf/internal/domain"
	"go-waf/internal/platform/logger"

	"go.uber.org/zap"
)

type Pipeline struct {
	cfg       *config.SecurityConfig
	engines   []domain.RuleEngine
	dlpEngine *engines.DlpEngine
	mu        sync.RWMutex
	scorer    *Scorer
}

func NewPipeline(cfg *config.SecurityConfig, ruleEngines ...domain.RuleEngine) *Pipeline {
	dlp, _ := engines.NewDlpEngine("./configs/rules/dlp_rules.json")
	return &Pipeline{
		cfg:       cfg,
		engines:   ruleEngines,
		dlpEngine: dlp,
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
			logger.Log.Debug("Rule Matched",
				zap.String("rule", event.RuleName),
				zap.Int("severity", int(event.Severity)),
			)
		}
	}

	if p.scorer.ShouldBlock(totalScore, p.cfg.BlockThreshold) {
		logger.Log.Warn("Request Blocked",
			zap.String("req_id", req.ID),
			zap.Int("total_score", totalScore),
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
