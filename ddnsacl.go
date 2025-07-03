package ddnsacl

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type Config struct {
	Domains     []string `json:"domains,omitempty"`
	RefreshSecs int      `json:"refreshSecs,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		RefreshSecs: 300, // default 5 minutes
	}
}

type DDNSACL struct {
	domains         []string
	refreshDur      time.Duration
	lastResolved    time.Time
	allowedIPs      map[string]struct{}
	allowedIPv6Nets []*net.IPNet
	mu              sync.RWMutex
	next            http.Handler
}

func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	acl := &DDNSACL{
		domains:         cfg.Domains,
		refreshDur:      time.Duration(cfg.RefreshSecs) * time.Second,
		allowedIPs:      make(map[string]struct{}),
		allowedIPv6Nets: []*net.IPNet{},
		next:            next,
	}

	if err := acl.resolveDomains(); err != nil {
		return nil, fmt.Errorf("initial DNS resolve failed: %w", err)
	}

	return acl, nil
}

func (a *DDNSACL) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Check if DNS refresh is needed
	if time.Since(a.lastResolved) > a.refreshDur {
		_ = a.resolveDomains() // Fail silently on refresh
	}

	ipStr, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	// IPv4 exact match
	if ip.To4() != nil {
		if _, ok := a.allowedIPs[ip.String()]; ok {
			a.next.ServeHTTP(rw, req)
			return
		}
	}

	// IPv6 prefix match
	if ip.To16() != nil && ip.To4() == nil {
		for _, subnet := range a.allowedIPv6Nets {
			if subnet.Contains(ip) {
				a.next.ServeHTTP(rw, req)
				return
			}
		}
	}

	http.Error(rw, "Forbidden", http.StatusForbidden)
}

func (a *DDNSACL) resolveDomains() error {
	resolvedIPv4 := make(map[string]struct{})
	resolvedIPv6 := []*net.IPNet{}

	for _, domain := range a.domains {
		ips, err := net.LookupIP(domain)
		if err != nil {
			continue // Fail silently per domain
		}

		for _, ip := range ips {
			if ip.To4() != nil {
				resolvedIPv4[ip.String()] = struct{}{}
			} else if ip.To16() != nil {
				// Match /64 subnet for IPv6
				ipnet := &net.IPNet{
					IP:   ip.Mask(net.CIDRMask(64, 128)),
					Mask: net.CIDRMask(64, 128),
				}
				resolvedIPv6 = append(resolvedIPv6, ipnet)
			}
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.allowedIPs = resolvedIPv4
	a.allowedIPv6Nets = resolvedIPv6
	a.lastResolved = time.Now()

	return nil
}
