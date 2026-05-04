package tls

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// ExtractClientFingerprint generates a JA3-like fingerprint from the TLS ClientHello.
// This is used for behavioral bot detection and client identification.
func ExtractClientFingerprint(hello *tls.ClientHelloInfo) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("%d", hello.SupportedVersions[0]))

	var ciphers []string
	for _, c := range hello.CipherSuites {
		ciphers = append(ciphers, fmt.Sprintf("%d", c))
	}
	parts = append(parts, strings.Join(ciphers, "-"))

	var curves []string
	for _, c := range hello.SupportedCurves {
		curves = append(curves, fmt.Sprintf("%d", c))
	}
	parts = append(parts, strings.Join(curves, "-"))

	var points []string
	for _, p := range hello.SupportedPoints {
		points = append(points, fmt.Sprintf("%d", p))
	}
	parts = append(parts, strings.Join(points, "-"))

	return strings.Join(parts, ",")
}
