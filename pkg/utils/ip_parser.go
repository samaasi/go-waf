package utils

import (
	"net"
	"strings"
)

// IPChecker handles single IPs and CIDR ranges
type IPChecker struct {
	BlockedIPs   map[string]bool
	BlockedCIDRs []*net.IPNet
}

func NewIPChecker() *IPChecker {
	return &IPChecker{
		BlockedIPs:   make(map[string]bool),
		BlockedCIDRs: make([]*net.IPNet, 0),
	}
}

func (c *IPChecker) Add(ipOrCidr string) error {
	if strings.Contains(ipOrCidr, "/") {
		_, network, err := net.ParseCIDR(ipOrCidr)
		if err != nil {
			return err
		}
		c.BlockedCIDRs = append(c.BlockedCIDRs, network)
	} else {
		c.BlockedIPs[ipOrCidr] = true
	}
	return nil
}

func (c *IPChecker) IsBlocked(ipStr string) bool {
	if c.BlockedIPs[ipStr] {
		return true
	}

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return false
	}

	for _, network := range c.BlockedCIDRs {
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}
