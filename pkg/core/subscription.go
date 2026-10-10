package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type SubscriptionPolicy struct {
	Allowlist []string
	MaxBytes  int64
}

// Conservative subscription policy includes special-purpose and translation ranges.
// https://www.iana.org/assignments/iana-ipv6-special-registry/
var reservedNetworks = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "100::/64", "100:0:0:1::/64", "2001:db8::/32", "2001::/32", "2001:2::/48", "2001:10::/28", "2001:20::/28", "2001:30::/28", "2002::/16", "3fff::/20", "5f00::/16", "64:ff9b::/96", "64:ff9b:1::/48"}

func publicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return false
	}
	for _, p := range reservedNetworks {
		if netip.MustParsePrefix(p).Contains(ip) {
			return false
		}
	}
	return true
}
func (p SubscriptionPolicy) allowed(host string) bool {
	for _, s := range p.Allowlist {
		if strings.EqualFold(strings.TrimSpace(s), host) {
			return true
		}
	}
	return false
}
func (p SubscriptionPolicy) validate(u *url.URL) error {
	if (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("subscription URL requires http(s), a host, and no embedded authentication")
	}
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil && !p.allowed(u.Hostname()) && !publicAddress(ip) {
		return fmt.Errorf("subscription destination is not public")
	}
	return nil
}
func (p SubscriptionPolicy) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if e != nil || len(ips) == 0 {
		return nil, fmt.Errorf("subscription DNS lookup failed")
	}
	for _, ip := range ips {
		if !p.allowed(host) && !publicAddress(ip) {
			return nil, fmt.Errorf("subscription DNS resolved to a restricted address")
		}
	}
	d := net.Dialer{Timeout: 8 * time.Second}
	for _, ip := range ips {
		if conn, e := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port)); e == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("subscription connection failed")
}
func FetchSubscriptionContext(ctx context.Context, subURL string, p SubscriptionPolicy) (string, error) {
	u, e := url.Parse(subURL)
	if e != nil {
		return "", fmt.Errorf("invalid subscription URL")
	}
	if e = p.validate(u); e != nil {
		return "", e
	}
	tr := &http.Transport{Proxy: nil, DialContext: p.dial, TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return p.validate(req.URL)
	}}
	req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if e != nil {
		return "", fmt.Errorf("invalid subscription request")
	}
	req.Header.Set("User-Agent", "ClashMeta NodePure/1.1")
	resp, e := client.Do(req)
	if e != nil {
		return "", fmt.Errorf("subscription fetch failed (check destination and network)")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("subscription HTTP %d", resp.StatusCode)
	}
	limit := p.MaxBytes
	if limit <= 0 {
		limit = 2 << 20
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if e != nil {
		return "", fmt.Errorf("subscription read failed")
	}
	if int64(len(b)) > limit {
		return "", fmt.Errorf("subscription exceeds size limit")
	}
	return string(b), nil
}
