package ratelimit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/internal/store"

	"github.com/go-redis/redis/v8"
	lru "github.com/hashicorp/golang-lru/v2"
)

type cacheEntry struct {
	allowed   bool
	remaining int64
	expiry    time.Time
}

type RedisLimiter struct {
	redis   *store.RedisClient
	logger  domain.Logger
	l1Cache *lru.Cache[string, cacheEntry]
}

func NewRedisLimiter(r *store.RedisClient, log domain.Logger) *RedisLimiter {
	c, _ := lru.New[string, cacheEntry](2048)
	return &RedisLimiter{
		redis:   r,
		logger:  log,
		l1Cache: c,
	}
}

const rateLimitLua = `
local rlKey = KEYS[1]
local tsKey = KEYS[2]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local maxScore = tonumber(ARGV[4])
local clearBefore = now - window

	// Behavioral blocking check
	local threatScore = tonumber(redis.call('GET', tsKey) or 0)
if threatScore >= maxScore then
    return {-1, threatScore}
end

	// Sliding window
	redis.call('ZREMRANGEBYSCORE', rlKey, '-inf', clearBefore)
local count = redis.call('ZCARD', rlKey)

if count < limit then
    redis.call('ZADD', rlKey, now, now)
    redis.call('EXPIRE', rlKey, window)
    return {1, limit - count - 1}
else
    return {0, 0}
end
`

func (r *RedisLimiter) Allow(ctx context.Context, key string, limit int, windowSeconds int) (bool, int64, error) {
	if r.l1Cache != nil {
		if entry, ok := r.l1Cache.Get(key); ok {
			if time.Now().Before(entry.expiry) {
				return entry.allowed, entry.remaining, nil
			}
		}
	}

	if r.redis == nil || r.redis.Client == nil {
		r.logger.Error("Rate limiter Redis client missing")
		return true, 0, nil
	}

	rlKey := fmt.Sprintf("waf:rl:%s", key)
	ipPart := strings.Split(key, ":")[0]
	tsKey := fmt.Sprintf("waf:ts:%s", ipPart)

	now := time.Now().Unix()
	maxScore := 100 // Threshold

	res, err := r.redis.Client.Eval(ctx, rateLimitLua, []string{rlKey, tsKey}, now, windowSeconds, limit, maxScore).Result()
	if err != nil {
		r.logger.Error("Rate limiter Redis Lua error", domain.Any("error", err))
		return true, 0, err
	}

	resList := res.([]interface{})
	status := resList[0].(int64)

	allowed := status == 1
	remaining := resList[1].(int64)

	// Update L1 Cache
	if r.l1Cache != nil {
		expiry := time.Now().Add(1 * time.Second) // default 1s cache
		if status == -1 {
			expiry = time.Now().Add(1 * time.Minute) // block 1m cache
			allowed = false
		}
		r.l1Cache.Add(key, cacheEntry{allowed: allowed, remaining: remaining, expiry: expiry})
	}

	return allowed, remaining, nil
}

func (r *RedisLimiter) ReportViolation(ctx context.Context, ip string, score int) error {
	if r.redis == nil || r.redis.Client == nil {
		return nil
	}
	tsKey := fmt.Sprintf("waf:ts:%s", ip)
	// Increment score and set 24h expiration on new violations
	_, err := r.redis.Client.IncrBy(ctx, tsKey, int64(score)).Result()
	if err == nil {
		r.redis.Client.Expire(ctx, tsKey, 24*time.Hour)
	}
	return err
}

func (r *RedisLimiter) GetThreatScore(ctx context.Context, ip string) (int, error) {
	if r.redis == nil || r.redis.Client == nil {
		return 0, nil
	}
	tsKey := fmt.Sprintf("waf:ts:%s", ip)
	val, err := r.redis.Client.Get(ctx, tsKey).Int()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}
