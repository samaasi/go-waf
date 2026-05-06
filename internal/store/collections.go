package store

import (
	"context"
	"fmt"
	"time"
)

type RedisCollectionStore struct {
	redis  *RedisClient
	prefix string
}

func NewRedisCollectionStore(redis *RedisClient) *RedisCollectionStore {
	return &RedisCollectionStore{
		redis:  redis,
		prefix: "waf:col",
	}
}

func (s *RedisCollectionStore) genKey(collection, id, key string) string {
	return fmt.Sprintf("%s:%s:%s:%s", s.prefix, collection, id, key)
}

func (s *RedisCollectionStore) Get(ctx context.Context, collection, id, key string) (string, error) {
	val, err := s.redis.Client.Get(ctx, s.genKey(collection, id, key)).Result()
	if err != nil {
		return "", nil // Treat missing as empty string, standard for WAF
	}
	return val, nil
}

func (s *RedisCollectionStore) Set(ctx context.Context, collection, id, key, value string, ttl time.Duration) error {
	return s.redis.Client.Set(ctx, s.genKey(collection, id, key), value, ttl).Err()
}

func (s *RedisCollectionStore) Increment(ctx context.Context, collection, id, key string, delta int, ttl time.Duration) (int, error) {
	fullKey := s.genKey(collection, id, key)
	pipe := s.redis.Client.Pipeline()
	incr := pipe.IncrBy(ctx, fullKey, int64(delta))
	if ttl > 0 {
		pipe.Expire(ctx, fullKey, ttl)
	}
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return int(incr.Val()), nil
}
