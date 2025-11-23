package ratelimit

import (
	"context"
	"fmt"
	"time"

	"go-waf/internal/platform/cache"
	"go-waf/internal/platform/logger"

	"go.uber.org/zap"
)

type RedisLimiter struct {
	redis *cache.RedisClient
}

func NewRedisLimiter(r *cache.RedisClient) *RedisLimiter {
	return &RedisLimiter{redis: r}
}

func (r *RedisLimiter) Allow(ctx context.Context, key string, limit int, windowSeconds int) (bool, int64, error) {
	// Key format: waf:ratelimit:192.168.1.1
	redisKey := fmt.Sprintf("waf:ratelimit:%s", key)
	expiration := time.Duration(windowSeconds) * time.Second

	// Atomic INCR. If key doesn't exist, Redis creates it with value 0, then increments to 1.
	count, err := r.redis.Increment(ctx, redisKey, expiration)
	if err != nil {
		// Fail open (allow traffic) if Redis is down, but log it: (robust option to be implemented.)
		logger.Log.Error("Rate limiter Redis error", zap.Error(err))
		return true, 0, nil
	}

	if count > int64(limit) {
		return false, 0, nil
	}

	return true, int64(limit) - count, nil
}
