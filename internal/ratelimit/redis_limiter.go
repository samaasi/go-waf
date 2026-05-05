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
	limiter := &RedisLimiter{
		redis:   r,
		logger:  log,
		l1Cache: c,
	}
	if r != nil && r.Client != nil {
		go limiter.listenForInvalidations()
	}
	return limiter
}

const (
	rateLimitLua = `
local rlKey = KEYS[1]
local tsKey = KEYS[2]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local maxScore = tonumber(ARGV[4])
local clearBefore = now - window

local threatScore = tonumber(redis.call('GET', tsKey) or 0)
if threatScore >= maxScore then
    return {-1, threatScore}
end

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
	invalidationChannel = "waf:cache:invalidate"
)

func (r *RedisLimiter) listenForInvalidations() {
	pubsub := r.redis.Client.Subscribe(context.Background(), invalidationChannel)
	defer pubsub.Close()

	ch := pubsub.Channel()
	for msg := range ch {
		ip := msg.Payload
		// Purge entries related to this IP from local L1 cache
		keys := r.l1Cache.Keys()
		for _, k := range keys {
			if strings.HasPrefix(k, ip) {
				r.l1Cache.Remove(k)
			}
		}
	}
}

func (r *RedisLimiter) Allow(ctx context.Context, key string, limit int, windowSeconds int) (bool, int64, error) {
	// ... (No change to Allow logic itself, but keeping structure)
	// (Re-pasting full logic for completeness in the file)
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

	res, err := r.redis.Client.Eval(ctx, `
local rlKey = KEYS[1]
local tsKey = KEYS[2]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local maxScore = tonumber(ARGV[4])
local clearBefore = now - window

local threatScore = tonumber(redis.call('GET', tsKey) or 0)
if threatScore >= maxScore then
    return {-1, threatScore}
end

redis.call('ZREMRANGEBYSCORE', rlKey, '-inf', clearBefore)
local count = redis.call('ZCARD', rlKey)

if count < limit then
    redis.call('ZADD', rlKey, now, now)
    redis.call('EXPIRE', rlKey, window)
    return {1, limit - count - 1}
else
    return {0, 0}
end
`, []string{rlKey, tsKey}, now, windowSeconds, limit, maxScore).Result()
	if err != nil {
		r.logger.Error("Rate limiter Redis Lua error", domain.Any("error", err))
		return true, 0, err
	}

	resList := res.([]interface{})
	status := resList[0].(int64)
	remaining := resList[1].(int64)
	allowed := status == 1

	if r.l1Cache != nil {
		expiry := time.Now().Add(1 * time.Second)
		if status == -1 {
			expiry = time.Now().Add(1 * time.Minute)
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
	_, err := r.redis.Client.IncrBy(ctx, tsKey, int64(score)).Result()
	if err == nil {
		r.redis.Client.Expire(ctx, tsKey, 24*time.Hour)
		// Broadcast invalidation to other nodes
		r.redis.Client.Publish(ctx, invalidationChannel, ip)
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
