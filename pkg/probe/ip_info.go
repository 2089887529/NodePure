package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/2089887529/NodePure/pkg/core"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type IPInfo struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Region      string `json:"region"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	ASN         string `json:"asn"`
	Org         string `json:"org"`
	Source      string `json:"source"`
	SourceAt    string `json:"source_at"`
	LookupError string `json:"lookup_error,omitempty"`
}

func NewProxyClient(n *core.ProxyNode, timeout time.Duration) (*http.Client, error) {
	u, e := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", n.LocalPort))
	if e != nil {
		return nil, e
	}
	u.User = url.UserPassword(n.ProxyUser, n.ProxyPassword)
	tr := &http.Transport{Proxy: http.ProxyURL(u), TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: timeout, MaxIdleConns: 10, IdleConnTimeout: 15 * time.Second}
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("redirect limit")
		}
		return nil
	}}, nil
}

type cacheEntry struct {
	info  IPInfo
	until time.Time
	ready chan struct{}
}
type ipCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
	slots   chan struct{}
	rateMu  sync.Mutex
	next    time.Time
}

var metadata = &ipCache{entries: map[string]*cacheEntry{}, slots: make(chan struct{}, 2)}

func readResponse(ctx context.Context, client *http.Client, address string) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", address, nil)
	if e != nil {
		return nil, fmt.Errorf("request failed")
	}
	req.Header.Set("User-Agent", "NodePure/1.1")
	resp, e := client.Do(req)
	if e != nil {
		return nil, fmt.Errorf("IP lookup network error")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("IP lookup HTTP %d", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if e != nil || len(b) > 64<<10 {
		return nil, fmt.Errorf("IP lookup read/size error")
	}
	return b, nil
}
func fetchTrace(ctx context.Context, client *http.Client) (*IPInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	b, e := readResponse(ctx, client, "https://www.cloudflare.com/cdn-cgi/trace")
	if e != nil {
		return nil, e
	}
	info := &IPInfo{Source: "cloudflare-trace", SourceAt: time.Now().UTC().Format(time.RFC3339)}
	for _, line := range strings.Split(string(b), "\n") {
		kv := strings.SplitN(line, "=", 2)
		if len(kv) == 2 {
			if kv[0] == "ip" {
				info.IP = strings.TrimSpace(kv[1])
			}
			if kv[0] == "loc" {
				info.CountryCode = strings.TrimSpace(kv[1])
				info.Country = info.CountryCode
			}
		}
	}
	if net.ParseIP(info.IP) == nil {
		return nil, fmt.Errorf("invalid exit IP")
	}
	return info, nil
}
func fetchWhois(ctx context.Context, client *http.Client, ip string) (*IPInfo, error) {
	if ip != "" && net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("invalid IP")
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	b, e := readResponse(ctx, client, "https://ipwho.is/"+ip)
	if e != nil {
		return nil, e
	}
	var v struct {
		Success     bool   `json:"success"`
		IP          string `json:"ip"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Region      string `json:"region"`
		City        string `json:"city"`
		Connection  struct {
			ASN int    `json:"asn"`
			ISP string `json:"isp"`
			Org string `json:"org"`
		} `json:"connection"`
	}
	if json.Unmarshal(b, &v) != nil || !v.Success || net.ParseIP(v.IP) == nil {
		return nil, fmt.Errorf("IP metadata unavailable")
	}
	if ip != "" && !net.ParseIP(ip).Equal(net.ParseIP(v.IP)) {
		return nil, fmt.Errorf("metadata IP mismatch")
	}
	asn := ""
	if v.Connection.ASN > 0 {
		asn = "AS" + strconv.Itoa(v.Connection.ASN)
	}
	return &IPInfo{IP: v.IP, Country: v.Country, CountryCode: v.CountryCode, Region: v.Region, City: v.City, ISP: v.Connection.ISP, ASN: asn, Org: v.Connection.Org, Source: "ipwho.is", SourceAt: time.Now().UTC().Format(time.RFC3339)}, nil
}
func (c *ipCache) lookup(ctx context.Context, client *http.Client, base *IPInfo) *IPInfo {
	ip := net.ParseIP(base.IP).String()
	for {
		c.mu.Lock()
		entry := c.entries[ip]
		if entry != nil && entry.ready != nil {
			ready := entry.ready
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				copy := *base
				copy.LookupError = "metadata canceled"
				return &copy
			case <-ready:
				continue
			}
		}
		if entry != nil && time.Now().Before(entry.until) {
			copy := entry.info
			c.mu.Unlock()
			return &copy
		}
		if len(c.entries) >= 4096 {
			for k, v := range c.entries {
				if v.ready == nil {
					delete(c.entries, k)
				}
			}
		}
		entry = &cacheEntry{ready: make(chan struct{})}
		c.entries[ip] = entry
		c.mu.Unlock()
		copy := *base
		ttl := 10 * time.Minute
		select {
		case <-ctx.Done():
			copy.LookupError = "metadata canceled"
			ttl = 15 * time.Second
		default:
			if info, e := c.limitedWhois(ctx, client, ip); e == nil {
				copy = *info
			} else {
				copy.LookupError = e.Error()
			}
			if copy.LookupError != "" {
				ttl = 30 * time.Second
			}
		}
		c.mu.Lock()
		entry.info = copy
		entry.until = time.Now().Add(ttl)
		close(entry.ready)
		entry.ready = nil
		c.mu.Unlock()
		return &copy
	}
}
func (c *ipCache) limitedWhois(ctx context.Context, client *http.Client, ip string) (*IPInfo, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("metadata canceled")
	case c.slots <- struct{}{}:
	}
	defer func() { <-c.slots }()
	c.rateMu.Lock()
	wait := time.Until(c.next)
	if wait < 0 {
		wait = 0
	}
	c.next = time.Now().Add(wait + 500*time.Millisecond)
	c.rateMu.Unlock()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("metadata canceled")
	case <-timer.C:
	}
	return fetchWhois(ctx, client, ip)
}
func FetchIPInfo(ctx context.Context, client *http.Client) (*IPInfo, error) {
	info, e := fetchTrace(ctx, client)
	if e != nil {
		info, e = metadata.limitedWhois(ctx, client, "")
		if e != nil {
			return nil, fmt.Errorf("未获取有效出口 IP；节点超时或服务不可用")
		}
		return info, nil
	}
	return metadata.lookup(ctx, client, info), nil
}
