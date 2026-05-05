package geoip

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
	"github.com/samaasi/go-waf/internal/domain"
)

var _ domain.GeoIPProvider = (*MaxMindDB)(nil)

var botKeywords = []string{
	"aws", "amazon", "google", "gcp", "azure", "microsoft", "digitalocean",
	"hetzner", "ovh", "linode", "vultr", "akamai", "cloudflare", "fastly",
	"datacenter", "hosting", "vpn", "proxy", "nordvpn", "expressvpn",
}

type MaxMindDB struct {
	cityDB   *geoip2.Reader
	asnDB    *geoip2.Reader
	cityPath string
	asnPath  string
	mu       sync.RWMutex
}

func NewMaxMindDB(cityPath, asnPath string) (*MaxMindDB, error) {
	cityReader, err := geoip2.Open(cityPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open city db: %w", err)
	}

	asnReader, _ := geoip2.Open(asnPath) // ASN is optional for basic functionality

	return &MaxMindDB{
		cityDB:   cityReader,
		asnDB:    asnReader,
		cityPath: cityPath,
		asnPath:  asnPath,
	}, nil
}

func (m *MaxMindDB) Lookup(ipStr string) (*domain.GeoIPResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP")
	}

	result := &domain.GeoIPResult{}

	if m.cityDB != nil {
		record, err := m.cityDB.City(ip)
		if err == nil {
			result.Country = record.Country.Names["en"]
			result.CountryCode = record.Country.IsoCode
			result.City = record.City.Names["en"]
			result.Latitude = record.Location.Latitude
			result.Longitude = record.Location.Longitude
			result.Timezone = record.Location.TimeZone
		}
	}

	if m.asnDB != nil {
		record, err := m.asnDB.ASN(ip)
		if err == nil {
			result.ASN = record.AutonomousSystemNumber
			result.Organization = record.AutonomousSystemOrganization
			
			org := strings.ToLower(result.Organization)
			for _, kw := range botKeywords {
				if strings.Contains(org, kw) {
					result.IsBot = true
					break
				}
			}
		}
	}

	return result, nil
}

func (m *MaxMindDB) GetCountry(ipStr string) (string, error) {
	res, err := m.Lookup(ipStr)
	if err != nil {
		return "", err
	}
	return res.CountryCode, nil
}

func (m *MaxMindDB) Reload() error {
	newCity, err := geoip2.Open(m.cityPath)
	if err != nil {
		return err
	}

	var newASN *geoip2.Reader
	if m.asnPath != "" {
		newASN, _ = geoip2.Open(m.asnPath)
	}

	m.mu.Lock()
	oldCity := m.cityDB
	oldASN := m.asnDB
	m.cityDB = newCity
	m.asnDB = newASN
	m.mu.Unlock()

	if oldCity != nil {
		oldCity.Close()
	}
	if oldASN != nil {
		oldASN.Close()
	}

	return nil
}

func (m *MaxMindDB) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cityDB != nil {
		m.cityDB.Close()
	}
	if m.asnDB != nil {
		m.asnDB.Close()
	}
}

type MockProvider struct{}

func (m *MockProvider) Lookup(ip string) (*domain.GeoIPResult, error) {
	return &domain.GeoIPResult{CountryCode: "US", Organization: "Mock ISP", IsBot: false}, nil
}
func (m *MockProvider) GetCountry(ip string) (string, error) { return "US", nil }
func (m *MockProvider) Reload() error                        { return nil }
func (m *MockProvider) Close()                               {}
