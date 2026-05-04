package geoip

import (
	"fmt"
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"
	"github.com/samaasi/go-waf/internal/domain"
)

// Ensure MaxMindDB implements domain.GeoIPProvider
var _ domain.GeoIPProvider = (*MaxMindDB)(nil)

type MaxMindDB struct {
	reader *geoip2.Reader
	mu     sync.RWMutex
}

func NewMaxMindDB(dbPath string) (*MaxMindDB, error) {
	reader, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open maxmind db: %w", err)
	}

	return &MaxMindDB{
		reader: reader,
	}, nil
}

// GetCountry returns the ISO country code (e.g., "US", "CN", "NG")
func (m *MaxMindDB) GetCountry(ipStr string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP format")
	}

	record, err := m.reader.Country(ip)
	if err != nil {
		return "", err
	}

	return record.Country.IsoCode, nil
}

func (m *MaxMindDB) Close() {
	if m.reader != nil {
		m.reader.Close()
	}
}

// MockProvider for testing when you don't have the real DB
type MockProvider struct{}

func (m *MockProvider) GetCountry(ip string) (string, error) { return "US", nil }
func (m *MockProvider) Close()                               {}
