package ratelimit

import "context"

type Limiter interface {
	// Allow checks if the key (IP) is allowed to proceed.
	// Returns: allowed (bool), remaining_requests (int64), error
	Allow(ctx context.Context, key string, limit int, windowSeconds int) (bool, int64, error)

	// ReportViolation increments the threat score for a given IP.
	ReportViolation(ctx context.Context, ip string, score int) error

	// GetThreatScore returns the current behavioral threat score for an IP.
	GetThreatScore(ctx context.Context, ip string) (int, error)
}
