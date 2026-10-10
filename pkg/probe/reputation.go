package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/2089887529/NodePure/pkg/config"
)

type reputationEntry struct {
	value *PurityAnalysis
	until time.Time
	ready chan struct{}
}

// One checker per server: explicit-IP queries use the server's connection and
// account budget, never rotate node exits to evade a provider's limits.
type ReputationChecker struct {
	provider, key string
	limit         int
	client        *http.Client
	mu            sync.Mutex
	entries       map[string]*reputationEntry
	slots         chan struct{}
	rateMu        sync.Mutex
	next          time.Time
	day           string
	used          int
}

func NewReputationChecker(cfg *config.Config) *ReputationChecker {
	return &ReputationChecker{provider: cfg.ReputationProvider, key: cfg.ProxycheckKey, limit: cfg.ReputationDailyLimit, entries: map[string]*reputationEntry{}, slots: make(chan struct{}, 2), client: &http.Client{Transport: &http.Transport{Proxy: nil, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 6 * time.Second, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}, Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func copyPurity(p *PurityAnalysis) *PurityAnalysis {
	cp := *p
	if p.FraudScore != nil {
		n := *p.FraudScore
		cp.FraudScore = &n
	}
	if p.PurityScore != nil {
		n := *p.PurityScore
		cp.PurityScore = &n
	}
	if p.Flags != nil {
		cp.Flags = map[string]bool{}
		for k, v := range p.Flags {
			cp.Flags[k] = v
		}
	}
	return &cp
}

func (r *ReputationChecker) Analyze(parent context.Context, nodeClient *http.Client, info *IPInfo) *PurityAnalysis {
	p := AnalyzePurity(info)
	if r.provider == "off" {
		p.Status = "disabled"
		p.Reason = "信誉查询已关闭"
		return p
	}
	if info == nil || net.ParseIP(info.IP) == nil {
		p.Reason = "没有有效出口 IP，无法查询评分"
		return p
	}
	ip := net.ParseIP(info.IP).String()
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	for {
		r.mu.Lock()
		entry := r.entries[ip]
		if entry != nil && entry.ready != nil {
			ready := entry.ready
			r.mu.Unlock()
			select {
			case <-ctx.Done():
				p.Status = "timeout"
				p.Reason = "等待信誉查询超时"
				return p
			case <-ready:
				continue
			}
		}
		if entry != nil && time.Now().Before(entry.until) {
			cp := copyPurity(entry.value)
			cp.Cached = true
			r.mu.Unlock()
			return cp
		}
		if len(r.entries) >= 4096 {
			for k, v := range r.entries {
				if v.ready == nil && time.Now().After(v.until) {
					delete(r.entries, k)
				}
			}
			if len(r.entries) >= 4096 {
				for k, v := range r.entries {
					if v.ready == nil {
						delete(r.entries, k)
						break
					}
				}
			}
		}
		entry = &reputationEntry{ready: make(chan struct{})}
		r.entries[ip] = entry
		r.mu.Unlock()
		p = r.lookup(ctx, nodeClient, info)
		ttl := time.Hour
		if !p.Verified {
			ttl = time.Minute
		}
		r.mu.Lock()
		entry.value = copyPurity(p)
		entry.until = time.Now().Add(ttl)
		close(entry.ready)
		entry.ready = nil
		r.mu.Unlock()
		return p
	}
}

func (r *ReputationChecker) lookup(ctx context.Context, nodeClient *http.Client, info *IPInfo) *PurityAnalysis {
	p := AnalyzePurity(info)
	if r.provider == "ippure" {
		p.Source = "IPPure"
		p.SourceURL = "https://ippure.com/MyIP-Info-API"
	} else {
		p.Source = "proxycheck.io v3"
		p.SourceURL = "https://proxycheck.io/api/#risk_score"
	}
	fail := func(status, reason string) *PurityAnalysis { p.Status = status; p.Reason = reason; return p }
	if ctx.Err() != nil {
		return fail("timeout", "信誉查询超时")
	}
	select {
	case <-ctx.Done():
		return fail("timeout", "信誉查询超时")
	case r.slots <- struct{}{}:
	}
	defer func() { <-r.slots }()
	r.rateMu.Lock()
	wait := time.Until(r.next)
	if wait < 0 {
		wait = 0
	}
	r.next = time.Now().Add(wait + 500*time.Millisecond)
	r.rateMu.Unlock()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fail("timeout", "信誉查询超时")
	case <-timer.C:
	}
	if ctx.Err() != nil {
		return fail("timeout", "信誉查询超时")
	}
	r.mu.Lock()
	day := time.Now().UTC().Format("2006-01-02")
	if day != r.day {
		r.day = day
		r.used = 0
	}
	if r.used >= r.limit {
		r.mu.Unlock()
		return fail("daily_limit", "本机今日信誉查询预算已用完；可配置自己的 API 配额")
	}
	r.used++
	r.mu.Unlock()
	ip := net.ParseIP(info.IP).String()
	address := "https://my.ippure.com/v1/info"
	client := r.client
	if r.provider == "proxycheck" {
		query := url.Values{"tag": {"0"}, "ver": {"24-June-2026"}}
		if r.key != "" {
			query.Set("key", r.key)
		}
		address = "https://proxycheck.io/v3/" + ip + "?" + query.Encode()
	} else if nodeClient != nil {
		cp := *nodeClient
		cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &cp
	} else {
		return fail("unavailable", "IPPure 当前出口接口需要通过目标节点访问")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", address, nil)
	if e != nil {
		return fail("error", "无法创建信誉查询")
	}
	req.Header.Set("User-Agent", "NodePure/1.2")
	req.Header.Set("Accept", "application/json")
	response, e := client.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return fail("timeout", "信誉查询超时")
		}
		return fail("network_error", "信誉数据源网络请求失败")
	}
	defer response.Body.Close()
	p.SourceAt = time.Now().UTC().Format(time.RFC3339)
	if response.StatusCode == 429 {
		return fail("rate_limited", "信誉数据源限流或配额已用完")
	}
	if response.StatusCode != 200 {
		return fail("http_error", fmt.Sprintf("信誉数据源返回 HTTP %d", response.StatusCode))
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if e != nil || len(data) > 64<<10 {
		return fail("invalid_response", "信誉响应读取失败或超出大小限制")
	}
	if r.provider == "ippure" {
		e = decodeIPPure(data, ip, p)
	} else {
		e = decodeProxycheck(data, ip, p)
	}
	if e != nil {
		return fail("invalid_response", e.Error())
	}
	return p
}

func applyRisk(p *PurityAnalysis, score *int) error {
	if score == nil || *score < 0 || *score > 100 {
		return fmt.Errorf("信誉数据源未提供有效的 0–100 风险分")
	}
	risk := *score
	purity := 100 - risk
	p.FraudScore = &risk
	p.PurityScore = &purity
	p.Verified = true
	p.Status = "ok"
	p.Confidence = "provider"
	p.Reason = "第三方原始风险分；纯净度 = 100 − 风险分，不代表账号或网站保证"
	switch {
	case risk <= 25:
		p.Grade = "A"
		p.RiskLevel = "low"
		p.RiskLabel = "低风险参考"
	case risk <= 50:
		p.Grade = "B"
		p.RiskLevel = "medium"
		p.RiskLabel = "中等风险参考"
	case risk <= 75:
		p.Grade = "C"
		p.RiskLevel = "high"
		p.RiskLabel = "较高风险参考"
	default:
		p.Grade = "D"
		p.RiskLevel = "very_high"
		p.RiskLabel = "高风险参考"
	}
	return nil
}

func decodeProxycheck(data []byte, ip string, p *PurityAnalysis) error {
	var top map[string]json.RawMessage
	if json.Unmarshal(data, &top) != nil {
		return fmt.Errorf("信誉响应不是有效 JSON")
	}
	var status string
	json.Unmarshal(top["status"], &status)
	if status != "ok" && status != "warning" {
		return fmt.Errorf("信誉数据源拒绝查询、鉴权失败或配额已用完")
	}
	var raw json.RawMessage
	for key, value := range top {
		if parsed := net.ParseIP(key); parsed != nil && parsed.Equal(net.ParseIP(ip)) {
			raw = value
			break
		}
	}
	if len(raw) == 0 {
		return fmt.Errorf("信誉响应的 IP 与检测出口不一致")
	}
	var v struct {
		Network struct {
			Type string `json:"type"`
		} `json:"network"`
		Detections struct {
			Risk        *int  `json:"risk"`
			Proxy       *bool `json:"proxy"`
			VPN         *bool `json:"vpn"`
			Tor         *bool `json:"tor"`
			Hosting     *bool `json:"hosting"`
			Anonymous   *bool `json:"anonymous"`
			Compromised *bool `json:"compromised"`
			Scraper     *bool `json:"scraper"`
		} `json:"detections"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return fmt.Errorf("信誉响应字段格式不正确")
	}
	if e := applyRisk(p, v.Detections.Risk); e != nil {
		return e
	}
	p.Flags = map[string]bool{}
	for k, v := range map[string]*bool{"proxy": v.Detections.Proxy, "vpn": v.Detections.VPN, "tor": v.Detections.Tor, "hosting": v.Detections.Hosting, "anonymous": v.Detections.Anonymous, "compromised": v.Detections.Compromised, "scraper": v.Detections.Scraper} {
		if v != nil {
			p.Flags[k] = *v
		}
	}
	switch strings.ToLower(v.Network.Type) {
	case "residential":
		p.IPType = "residential"
		p.IPTypeLabel = "住宅（数据源分类）"
		p.TypeVerified = true
	case "hosting":
		p.IPType = "datacenter"
		p.IPTypeLabel = "机房（数据源分类）"
		p.TypeVerified = true
	case "wireless":
		p.IPType = "wireless"
		p.IPTypeLabel = "移动/无线网络"
		p.TypeVerified = true
	case "business":
		p.IPType = "business"
		p.IPTypeLabel = "企业网络"
		p.TypeVerified = true
	}
	return nil
}

func decodeIPPure(data []byte, ip string, p *PurityAnalysis) error {
	var v struct {
		IP          string `json:"ip"`
		Risk        *int   `json:"fraudScore"`
		Residential *bool  `json:"isResidential"`
		Broadcast   *bool  `json:"isBroadcast"`
	}
	if json.Unmarshal(data, &v) != nil {
		return fmt.Errorf("IPPure 响应字段格式不正确")
	}
	parsed := net.ParseIP(v.IP)
	if parsed == nil || !parsed.Equal(net.ParseIP(ip)) {
		return fmt.Errorf("IPPure 观测的出口与检测 IP 不一致，评分不归入当前 IP")
	}
	if parsed.To4() == nil {
		return fmt.Errorf("IPPure 暂不提供 IPv6 风险分")
	}
	if e := applyRisk(p, v.Risk); e != nil {
		return e
	}
	if v.Residential != nil {
		p.TypeVerified = true
		if *v.Residential {
			p.IPType = "residential"
			p.IPTypeLabel = "住宅（IPPure分类）"
		} else {
			p.IPType = "non_residential"
			p.IPTypeLabel = "非住宅（IPPure分类）"
		}
	}
	if v.Broadcast != nil {
		if *v.Broadcast {
			p.Nativeness = "non_native"
			p.NativeLabel = "广播 IP（IPPure分类）"
		} else {
			p.Nativeness = "native"
			p.NativeLabel = "原生 IP（IPPure分类）"
		}
	}
	return nil
}
