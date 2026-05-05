package store

import (
	"context"
	"fmt"
	"time"

	"github.com/samaasi/go-waf/internal/config"
	"github.com/samaasi/go-waf/internal/domain"

	"github.com/go-redis/redis/v8"
)

type RedisClient struct {
	Client *redis.Client
	logger domain.Logger
}

func NewRedisClient(cfg config.RedisConfig, log domain.Logger) (*RedisClient, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     20, // Tuned for high-throughput WAF workloads
		MinIdleConns: 5,  // Keep warm connections ready
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := rdb.Ping(ctx).Result(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis at %s:%d: %w", cfg.Host, cfg.Port, err)
	}

	log.Info("Redis connected", domain.String("addr", fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)))

	return &RedisClient{Client: rdb, logger: log}, nil
}

func (r *RedisClient) Increment(ctx context.Context, key string, expiration time.Duration) (int64, error) {
	pipe := r.Client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, expiration)
	_, err := pipe.Exec(ctx)
	return incr.Val(), err
}

func (r *RedisClient) Close() error {
	r.logger.Info("Closing Redis connection pool")
	return r.Client.Close()
}
