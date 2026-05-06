package domain

import (
	"context"
	"time"
)

// CollectionStore defines the interface for managing persistent WAF state (IP, Session, etc).
type CollectionStore interface {
	Get(ctx context.Context, collection, id, key string) (string, error)
	Set(ctx context.Context, collection, id, key, value string, ttl time.Duration) error
	Increment(ctx context.Context, collection, id, key string, delta int, ttl time.Duration) (int, error)
}
