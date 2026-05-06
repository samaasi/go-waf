package engines

import (
	"context"
	"fmt"

	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/pkg/utils"
)

// StatisticalModel detects anomalies based on heuristics and math.
// It catches attacks that don't match known signatures (Zero-Day protection).
type StatisticalModel struct {
	entropyThreshold float64 // e.g., 5.5
	specialCharLimit float64 // e.g., 30% of string
}

func NewStatisticalModel() *StatisticalModel {
	return &StatisticalModel{
		entropyThreshold: 5.8,  // Encrypted/Obfuscated payloads usually > 6.0
		specialCharLimit: 0.35, // If >35% of body is special chars, it's suspicious
	}
}

func (m *StatisticalModel) ID() string                { return "ml-stat-anomaly" }
func (m *StatisticalModel) Name() string              { return "Statistical Anomaly Detector" }
func (m *StatisticalModel) Tags() []string            { return []string{"ml", "heuristic"} }
func (m *StatisticalModel) Severity() domain.Severity { return domain.SeverityHigh }

func (m *StatisticalModel) GetRules() []domain.RuleMetadata {
	return []domain.RuleMetadata{
		{ID: "ML-CLIENT-ANOMALY", Name: "Imposter Client Detection", Severity: domain.SeverityMedium, Enabled: true, EngineID: m.ID()},
		{ID: "ML-ANOMALY-AGGREGATE", Name: "Statistical Anomaly Fusion", Severity: domain.SeverityHigh, Enabled: true, EngineID: m.ID()},
	}
}

func (m *StatisticalModel) ToggleRule(id string, enabled bool) bool {
	return false
}

func (m *StatisticalModel) Evaluate(ctx context.Context, req *domain.WafRequest, phase int) []*domain.SecurityEvent {
	var events []*domain.SecurityEvent

	if phase == 1 {
		// High-Fidelity Client Fingerprinting
		ua := req.Headers.Get("User-Agent")
		imposterScore := utils.VerifyClientFingerprint(req.Method, ua, req.Headers)

		if imposterScore >= 40.0 {
			severity := domain.SeverityMedium
			if imposterScore >= 70.0 {
				severity = domain.SeverityHigh
			}

			events = append(events, &domain.SecurityEvent{
				RuleID:   "ML-CLIENT-ANOMALY",
				RuleName: "Imposter Client Profile",
				Severity: severity,
				Message:  fmt.Sprintf("Client fingerprinting indicates high probability of bot impersonation (Score: %.0f)", imposterScore),
			})
		}
	}

	if phase == 2 && len(req.Body) > 0 {
		bodyStr := utils.SampleString(string(req.Body), 2048)
		anomalyScore := 0.0

		// 1. KL-Divergence (Structural Anomaly)
		klDiv := utils.CalculateKLDivergence(bodyStr)
		if klDiv > 6.0 { // Threshold for significant structural deviation
			anomalyScore += 40
		}

		// 2. Entropy Check
		ent := utils.CalculateEntropy(bodyStr)
		if ent > m.entropyThreshold {
			anomalyScore += 30
		}

		// 3. N-gram Suspicion
		ngScore := utils.ScoreNgrams(bodyStr)
		if ngScore > 0.8 {
			anomalyScore += 30
		}

		// 4. Special Character Ratio
		specialCount := 0
		for i := 0; i < len(bodyStr); i++ {
			b := bodyStr[i]
			if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == ' ') {
				specialCount++
			}
		}
		ratio := float64(specialCount) / float64(len(bodyStr))
		if ratio > m.specialCharLimit {
			anomalyScore += 20
		}

		// Trigger based on Cumulative Anomaly Score
		if anomalyScore >= 50 {
			severity := domain.SeverityMedium
			if anomalyScore >= 80 {
				severity = domain.SeverityHigh
			}

			events = append(events, &domain.SecurityEvent{
				RuleID:      "ML-ANOMALY-AGGREGATE",
				RuleName:    "High-Dimensional Statistical Anomaly",
				Severity:    severity,
				Message:     fmt.Sprintf("Multiple statistical signals indicate non-human payload (Score: %.0f)", anomalyScore),
				MatchedData: fmt.Sprintf("KL:%.2f, Ent:%.2f, NG:%.2f", klDiv, ent, ngScore),
			})
		}
	}

	return events
}

func (m *StatisticalModel) LoadRules() error { return nil }
