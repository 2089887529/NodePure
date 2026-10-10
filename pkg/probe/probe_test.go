package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/2089887529/NodePure/pkg/core"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (fn roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }
func reply(r *http.Request, code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}
}
func TestServiceWaitsAndValidatesHTTP(t *testing.T) {
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		code := 200
		if strings.Contains(r.URL.Host, "cloudflare") {
			code = 500
		}
		if strings.Contains(r.URL.Host, "gstatic") {
			code = 500
		}
		if r.URL.Host == "chatgpt.com" || r.URL.Host == "claude.ai" {
			time.Sleep(350 * time.Millisecond)
			code = 403
		}
		return reply(r, code, ""), nil
	})}
	start := time.Now()
	s, m := CheckServices(context.Background(), client)
	if time.Since(start) < 350*time.Millisecond {
		t.Fatal("returned before AI result")
	}
	if s.Google != "error" || s.ChatGPT != "restricted" || s.Claude != "restricted" || m.HTTPRTT != -1 {
		t.Fatal("false positive", s, m)
	}
	before, _ := json.Marshal(s)
	time.Sleep(50 * time.Millisecond)
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("result mutated after return")
	}
}
func TestServicesCancellation(t *testing.T) {
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	s, _ := CheckServices(ctx, client)
	if time.Since(start) > time.Second || s.ChatGPT != "timeout" || s.Google != "timeout" {
		t.Fatal("cancellation ignored")
	}
}
func TestUnknownPurity(t *testing.T) {
	for _, info := range []*IPInfo{nil, {IP: "203.0.113.1"}, {IP: "1.1.1.1", ISP: "Comcast", ASN: "AS7922"}, {IP: "100.100.100.100", ISP: "Comcast", ASN: "AS7922"}} {
		p := AnalyzePurity(info)
		if p.FraudScore != nil || p.PurityScore != nil || p.Verified || p.Nativeness != "unknown" {
			t.Fatal("fabricated measurement")
		}
	}
}
func TestMetadataDeduplicatedAndValidated(t *testing.T) {
	var calls atomic.Int32
	cache := &ipCache{entries: map[string]*cacheEntry{}, slots: make(chan struct{}, 2)}
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return reply(r, 200, `{"success":true,"ip":"8.8.8.8","country":"United States","connection":{"asn":15169,"isp":"Google LLC"}}`), nil
	})}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info := cache.lookup(context.Background(), client, &IPInfo{IP: "8.8.8.8"})
			if info.ASN != "AS15169" {
				t.Error("metadata missing")
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("duplicate metadata requests", calls.Load())
	}
	client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		return reply(r, 200, `{"success":true,"ip":"1.1.1.1"}`), nil
	})
	if _, e := fetchWhois(context.Background(), client, "8.8.8.8"); e == nil {
		t.Fatal("wrong IP metadata accepted")
	}
}
func TestIPValidationAndLimits(t *testing.T) {
	for _, body := range []string{"ip=<img src=x onerror=alert(1)>\nloc=US", strings.Repeat("x", (64<<10)+1)} {
		client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) { return reply(r, 200, body), nil })}
		if _, e := fetchTrace(context.Background(), client); e == nil {
			t.Fatal("invalid trace accepted")
		}
	}
}
func TestEngineCancellation(t *testing.T) {
	e := NewEngine(2)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	nodes := []*core.ProxyNode{{ID: "1", LocalPort: 1}, {ID: "2", LocalPort: 1}}
	start := time.Now()
	e.Run(ctx, nodes, 100, func(*ProbeResult) { calls.Add(1) })
	if calls.Load() != 0 || time.Since(start) > time.Second {
		t.Fatal("canceled nodes dispatched")
	}
}
func TestResultJSONHidesCredentials(t *testing.T) {
	b, e := json.Marshal(&ProbeResult{RawConfig: map[string]interface{}{"password": "SYNTHETIC_SECRET"}})
	if e != nil || strings.Contains(string(b), "SYNTHETIC_SECRET") || strings.Contains(string(b), "raw_config") {
		t.Fatal(fmt.Sprint(e), "secret serialized")
	}
}
