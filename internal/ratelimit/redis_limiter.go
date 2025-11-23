package ratelimit

import (
    "context"
    "fmt"
    "time"

    "go-waf/internal/platform/cache"
    "go-waf/internal/platform/logger"

    "github.com/go-redis/redis/v8"
    "go.uber.org/zap"
)

type RedisLimiter struct {
	redis *cache.RedisClient
}

func NewRedisLimiter(r *cache.RedisClient) *RedisLimiter {
	return &RedisLimiter{redis: r}
}

func (r *RedisLimiter) Allow(ctx context.Context, key string, limit int, windowSeconds int) (bool, int64, error) {
    redisKey := fmt.Sprintf("waf:rl:%s", key)
    now := time.Now().Unix()
    windowStart := now - int64(windowSeconds)
    z := r.redis.Client
    if z == nil {
        return true, 0, fmt.Errorf("redis client not initialized")
    }
    _, err := z.ZAdd(ctx, redisKey, &redis.Z{Score: float64(now), Member: now}).Result()
    if err != nil {
        logger.Log.Error("Rate limiter Redis error", zap.Error(err))
        return true, 0, nil
    }
    _, _ = z.ZRemRangeByScore(ctx, redisKey, "-inf", fmt.Sprintf("%d", windowStart)).Result()
    count, err := z.ZCard(ctx, redisKey).Result()
    if err != nil {
        logger.Log.Error("Rate limiter Redis error", zap.Error(err))
        return true, 0, nil
    }
    _ = z.Expire(ctx, redisKey, time.Duration(windowSeconds)*time.Second).Err()
    if count > int64(limit) {
        return false, 0, nil
    }
    return true, int64(limit) - count, nil
}
