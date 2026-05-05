package domain

// GeoIPResult contains detailed location and network information for an IP.
type GeoIPResult struct {
	Country      string  `json:"country"`
	CountryCode  string  `json:"country_code"`
	City         string  `json:"city"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	Timezone     string  `json:"timezone"`
	ASN          uint    `json:"asn"`
	Organization string  `json:"organization"`
	IsBot        bool    `json:"is_bot"` // True if detected as Data Center/VPN
}

// GeoIPProvider defines the interface for mapping IP addresses to geographic locations and network intel.
type GeoIPProvider interface {
	Lookup(ip string) (*GeoIPResult, error)
	GetCountry(ip string) (string, error) // Keep for backward compatibility
	Reload() error
	Close()
}
