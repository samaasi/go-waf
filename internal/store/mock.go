package store

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type MockCollectionStore struct {
	data map[string]string
	mu   sync.RWMutex
}

func NewMockCollectionStore() *MockCollectionStore {
	return &MockCollectionStore{
		data: make(map[string]string),
	}
}

func (m *MockCollectionStore) Get(ctx context.Context, collection, id, key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	fullKey := fmt.Sprintf("%s:%s:%s", collection, id, key)
	return m.data[fullKey], nil
}

func (m *MockCollectionStore) Set(ctx context.Context, collection, id, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	fullKey := fmt.Sprintf("%s:%s:%s", collection, id, key)
	m.data[fullKey] = value
	return nil
}

func (m *MockCollectionStore) Increment(ctx context.Context, collection, id, key string, delta int, ttl time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fullKey := fmt.Sprintf("%s:%s:%s", collection, id, key)
	var current int
	fmt.Sscanf(m.data[fullKey], "%d", &current)
	newVal := current + delta
	m.data[fullKey] = fmt.Sprintf("%d", newVal)
	return newVal, nil
}
