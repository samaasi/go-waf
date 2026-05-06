package analysis

import (
	"context"
	"fmt"
	"net/http"
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

func (p *Pipeline) Inspect(ctx context.Context, req *domain.WafRequest) (domain.Action, []*domain.SecurityEvent) {
	cfg := p.snapshotConfig()
	var totalScore int
	var allEvents []*domain.SecurityEvent
	var mu sync.Mutex

	// Sequential Phase execution: Phase 1 (Headers/Path) -> Phase 2 (Body)
	for phase := 1; phase <= 2; phase++ {
		// Fast Match (Aho-Corasick) first for early short-circuit
		var fastMatchEvents []*domain.SecurityEvent
		for _, engine := range p.engines {
			if engine.ID() == "fast-match" {
				fastMatchEvents = engine.Evaluate(ctx, req, phase)
				break
			}
		}

		if len(fastMatchEvents) > 0 {
			p.exporter.Export(fastMatchEvents...)
			mu.Lock()
			allEvents = append(allEvents, fastMatchEvents...)
			totalScore += p.scorer.CalculateScore(fastMatchEvents)
			isBlocking := p.scorer.ShouldBlock(totalScore, cfg.BlockThreshold)
			mu.Unlock()

			if isBlocking {
				return domain.ActionBlock, allEvents
			}
		}

		// Parallel Deep Inspection for other engines in this phase
		g, gCtx := errgroup.WithContext(ctx)
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

				events := e.Evaluate(gCtx, req, phase)
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
				domain.Int("phase", phase),
				domain.Int("total_score", totalScore),
			)
			return domain.ActionBlock, allEvents
		}
	}

	return domain.ActionAllow, allEvents
}

func (p *Pipeline) InspectResponse(ctx context.Context, req *domain.WafRequest, phase int) (domain.Action, []*domain.SecurityEvent, []byte) {
	if phase < 3 || phase > 4 {
		return domain.ActionAllow, nil, req.ResponseBody
	}

	cfg := p.snapshotConfig()
	var allEvents []*domain.SecurityEvent
	var mu sync.Mutex

	// Phase 3 specific: Header Sanitization
	if phase == 3 {
		sanitized := p.sanitizeResponseHeaders(req.ResponseHeaders)
		if sanitized {
			// Headers modified in place, we can log this as an event if needed
			allEvents = append(allEvents, &domain.SecurityEvent{
				RuleID:   "WAF-FILTER-HEADERS",
				RuleName: "Response Header Sanitization",
				Severity: domain.SeverityLow,
				Message:  "Stripped dangerous server metadata headers",
			})
		}
	}

	// Phase 4 specific: DLP Engine
	if phase == 4 && p.dlpEngine != nil && cfg.Dlp.Enabled {
		dlpEvents := p.dlpEngine.InspectResponse(req.ResponseBody)
		if len(dlpEvents) > 0 {
			p.exporter.Export(dlpEvents...)
			allEvents = append(allEvents, dlpEvents...)

			if cfg.Dlp.Action == "mask" {
				maskedBody := p.dlpEngine.Mask(req.ResponseBody)
				return domain.ActionAllow, allEvents, maskedBody
			}
			return domain.ActionBlock, allEvents, req.ResponseBody
		}
	}

	// Deep Inspection for other engines in Phase 3/4
	g, gCtx := errgroup.WithContext(ctx)
	for _, engine := range p.engines {
		e := engine
		g.Go(func() error {
			select {
			case <-gCtx.Done():
				return nil
			default:
			}

			events := e.Evaluate(gCtx, req, phase)
			if len(events) > 0 {
				p.exporter.Export(events...)
				mu.Lock()
				allEvents = append(allEvents, events...)
				mu.Unlock()
			}
			return nil
		})
	}
	_ = g.Wait()

	if len(allEvents) > 0 && p.scorer.ShouldBlock(p.scorer.CalculateScore(allEvents), cfg.BlockThreshold) {
		return domain.ActionBlock, allEvents, req.ResponseBody
	}

	return domain.ActionAllow, allEvents, req.ResponseBody
}

func (p *Pipeline) UpdateConfig(newCfg *config.SecurityConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = newCfg
	p.logger.Info("Security configuration updated dynamically")
}

func (p *Pipeline) GetRules() []domain.RuleMetadata {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var allRules []domain.RuleMetadata
	for _, engine := range p.engines {
		allRules = append(allRules, engine.GetRules()...)
	}
	return allRules
}

func (p *Pipeline) ToggleRule(id string, enabled bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, engine := range p.engines {
		if engine.ToggleRule(id, enabled) {
			return true
		}
	}
	return false
}

func (p *Pipeline) CountEngines() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.engines)
}

func (p *Pipeline) FinishTransaction(req *domain.WafRequest, events []*domain.SecurityEvent) {
	if len(events) == 0 {
		return
	}
	p.exporter.LogTransaction(req, events)
}

func (p *Pipeline) sanitizeResponseHeaders(headers http.Header) bool {
	dangerousHeaders := []string{
		"Server",
		"X-Powered-By",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
		"X-Generator",
		"X-Runtime",
		"Via",
		"X-Varnish",
	}

	modified := false
	for _, h := range dangerousHeaders {
		if headers.Get(h) != "" {
			headers.Del(h)
			modified = true
		}
	}

	// Always add security headers if missing
	if headers.Get("X-Content-Type-Options") == "" {
		headers.Set("X-Content-Type-Options", "nosniff")
		modified = true
	}
	if headers.Get("X-Frame-Options") == "" {
		headers.Set("X-Frame-Options", "SAMEORIGIN")
		modified = true
	}

	return modified
}
