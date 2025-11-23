package ratelimit

import "context"

type Limiter interface {
	// Allow checks if the key (IP) is allowed to proceed.
	// Returns: allowed (bool), remaining_requests (int64), error
	Allow(ctx context.Context, key string, limit int, windowSeconds int) (bool, int64, error)
}
