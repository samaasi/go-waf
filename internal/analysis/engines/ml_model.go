package engines

import (
	"strings"

	"go-waf/internal/domain"
	"go-waf/pkg/utils"
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

func (m *StatisticalModel) Evaluate(req *domain.WafRequest) []*domain.SecurityEvent {
	var events []*domain.SecurityEvent

	if len(req.Body) > 0 {
		bodyStr := string(req.Body)

		ent := utils.CalculateEntropy(bodyStr)
		if ent > m.entropyThreshold {
			events = append(events, &domain.SecurityEvent{
				RuleID:      "ML-ENTROPY",
				RuleName:    "High Entropy (Potential Encrypted Payload)",
				Severity:    domain.SeverityHigh,
				Message:     "Request body entropy too high",
				MatchedData: "entropy_val", // In real ML, store the vector
			})
		}

		specialCount := 0
		for _, r := range bodyStr {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ", r) {
				specialCount++
			}
		}

		ratio := float64(specialCount) / float64(len(bodyStr))
		if ratio > m.specialCharLimit {
			events = append(events, &domain.SecurityEvent{
				RuleID:      "ML-NOISE",
				RuleName:    "High Signal-to-Noise Ratio",
				Severity:    domain.SeverityMedium,
				Message:     "Too many special characters",
				MatchedData: "noise_ratio",
			})
		}
	}

	return events
}

func (m *StatisticalModel) LoadRules() error { return nil }
