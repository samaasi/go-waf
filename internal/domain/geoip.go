package domain

// GeoIPProvider defines the interface for mapping IP addresses to geographic locations.
type GeoIPProvider interface {
	GetCountry(ip string) (string, error)
	Close()
}
