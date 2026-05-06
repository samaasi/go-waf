package analysis

import (
	"github.com/samaasi/go-waf/internal/domain"
)

// Scorer centralizes the logic of converting severities into a threat score.
type Scorer struct {
	weights map[domain.Severity]int
}

func NewScorer() *Scorer {
	return &Scorer{
		weights: map[domain.Severity]int{
			domain.SeverityCritical: 50,
			domain.SeverityHigh:     25,
			domain.SeverityMedium:   10,
			domain.SeverityLow:      2,
		},
	}
}

// CalculateScore computes the total threat score for a list of events.
func (s *Scorer) CalculateScore(events []*domain.SecurityEvent) int {
	total := 0
	for _, event := range events {
		if event.Severity == 0 {
			continue
		}
		if val, ok := s.weights[event.Severity]; ok {
			total += val
		} else {
			total += 1 // Fallback
		}
	}
	return total
}

// ShouldBlock determines if the score warrants a block based on the threshold.
func (s *Scorer) ShouldBlock(score, threshold int) bool {
	return score >= threshold
}
