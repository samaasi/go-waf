package utils

import (
	"github.com/corazawaf/libinjection-go"
)

// IsSQLi checks for SQL injection using libinjection.
func IsSQLi(s string) (bool, string) {
	return libinjection.IsSQLi(s)
}

// IsXSS checks for XSS using libinjection's XSS detection.
func IsXSS(s string) bool {
	return libinjection.IsXSS(s)
}
