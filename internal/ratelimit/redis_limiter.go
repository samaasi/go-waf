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

const rateLimitLua = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local clearBefore = now - window

redis.call('ZREMRANGEBYSCORE', key, '-inf', clearBefore)
local count = redis.call('ZCARD', key)

if count < limit then
    redis.call('ZADD', key, now, now)
    redis.call('EXPIRE', key, window)
    return {1, limit - count - 1}
else
    return {0, 0}
end
`

func (r *RedisLimiter) Allow(ctx context.Context, key string, limit int, windowSeconds int) (bool, int64, error) {
	if r.redis == nil || r.redis.Client == nil {
		if logger.Log != nil {
			logger.Log.Error("Rate limiter Redis client missing")
		}
		return true, 0, nil
	}

	redisKey := fmt.Sprintf("waf:rl:%s", key)
	now := time.Now().Unix()

	res, err := r.redis.Client.Eval(ctx, rateLimitLua, []string{redisKey}, now, windowSeconds, limit).Result()
	if err != nil {
		if logger.Log != nil {
			logger.Log.Error("Rate limiter Redis Lua error", zap.Error(err))
		}
		return true, 0, err
	}

	resList := res.([]interface{})
	allowed := resList[0].(int64) == 1
	remaining := resList[1].(int64)

	return allowed, remaining, nil
}
