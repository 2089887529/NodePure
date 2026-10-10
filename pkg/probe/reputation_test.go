package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2089887529/NodePure/pkg/config"
)

type reputationTransport func(*http.Request) (*http.Response, error)

func (f reputationTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
func reputationResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
func reputationJSON(ip, score string) string {
	return fmt.Sprintf(`{"status":"ok","%s":{"network":{"type":"Residential"},"detections":{"risk":%s,"proxy":false,"vpn":true}}}`, ip, score)
}

func TestRiskValidationAndBoundaries(t *testing.T) {
	for _, score := range []string{"0", "20", "25", "26", "50", "51", "75", "76", "100", "null", "-1", "101", "1.5", `"20"`} {
		t.Run(score, func(t *testing.T) {
			p := AnalyzePurity(&IPInfo{IP: "8.8.8.8"})
			err := decodeProxycheck([]byte(reputationJSON("8.8.8.8", score)), "8.8.8.8", p)
			valid := score == "0" || score == "20" || score == "25" || score == "26" || score == "50" || score == "51" || score == "75" || score == "76" || score == "100"
			if !valid {
				if err == nil || p.Verified || p.PurityScore != nil || p.FraudScore != nil {
					t.Fatal("invalid or missing score became a rating")
				}
				return
			}
			if err != nil || !p.Verified || !p.TypeVerified || p.IPType != "residential" || *p.FraudScore+*p.PurityScore != 100 || p.Flags["proxy"] || !p.Flags["vpn"] {
				t.Fatal("invalid valid-score mapping", err, p)
			}
			if _, present := p.Flags["tor"]; present {
				t.Fatal("missing flag treated as false")
			}
			want := "A"
			if *p.FraudScore > 75 {
				want = "D"
			} else if *p.FraudScore > 50 {
				want = "C"
			} else if *p.FraudScore > 25 {
				want = "B"
			}
			if p.Grade != want {
				t.Fatal("wrong risk band")
			}
		})
	}
	for _, body := range []string{`{"status":"ok","8.8.8.8":{"detections":{}}}`, reputationJSON("1.1.1.1", "0"), `{"status":"denied"}`, `not json`} {
		p := AnalyzePurity(nil)
		if decodeProxycheck([]byte(body), "8.8.8.8", p) == nil || p.Verified {
			t.Fatal("bad response accepted")
		}
	}
	p := AnalyzePurity(nil)
	if err := decodeProxycheck([]byte(reputationJSON("2001:4860:4860:0:0:0:0:8888", "0")), "2001:4860:4860::8888", p); err != nil || !p.Verified {
		t.Fatal("canonical IPv6 rejected", err)
	}
}

func TestIPPureExitBinding(t *testing.T) {
	p := AnalyzePurity(nil)
	if err := decodeIPPure([]byte(`{"ip":"8.8.8.8","fraudScore":0,"isResidential":false,"isBroadcast":false}`), "8.8.8.8", p); err != nil || *p.PurityScore != 100 || p.IPType != "non_residential" || p.Nativeness != "native" {
		t.Fatal("IPPure mapping", err)
	}
	for _, body := range []string{`{"ip":"1.1.1.1","fraudScore":0}`, `{"ip":"8.8.8.8"}`, `{"ip":"8.8.8.8","fraudScore":null}`, `{"ip":"2001:4860::8888","fraudScore":0}`} {
		p := AnalyzePurity(nil)
		ip := "8.8.8.8"
		if strings.Contains(body, "2001:") {
			ip = "2001:4860::8888"
		}
		if decodeIPPure([]byte(body), ip, p) == nil || p.Verified {
			t.Fatal("wrong exit or unavailable score accepted")
		}
	}
}

func TestReputationDeduplicatesAndCopies(t *testing.T) {
	cfg := config.Defaults()
	cfg.ProxycheckKey = "test-only-key"
	checker := NewReputationChecker(cfg)
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	checker.client.Transport = reputationTransport(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		if req.URL.Host != "proxycheck.io" || req.URL.Path != "/v3/8.8.8.8" || req.URL.Query().Get("tag") != "0" || req.URL.Query().Get("ver") != "24-June-2026" || req.URL.Query().Get("key") != cfg.ProxycheckKey {
			t.Error("incorrect explicit-IP request")
		}
		close(entered)
		<-release
		return reputationResponse(200, reputationJSON("8.8.8.8", "20")), nil
	})
	nodeClient := &http.Client{Transport: reputationTransport(func(*http.Request) (*http.Response, error) {
		t.Error("explicit IP query rotated through node")
		return nil, errors.New("unexpected")
	})}
	results := make([]*PurityAnalysis, 12)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = checker.Analyze(context.Background(), nodeClient, &IPInfo{IP: "8.8.8.8"})
		}(i)
	}
	<-entered
	close(release)
	wg.Wait()
	if calls.Load() != 1 || checker.used != 1 {
		t.Fatal("duplicate queries consumed budget")
	}
	for _, p := range results {
		if !p.Verified || p.Source != "proxycheck.io v3" || p.SourceAt == "" {
			t.Fatal("missing score provenance")
		}
	}
	*results[0].PurityScore = 7
	results[0].Flags["vpn"] = false
	p := checker.Analyze(context.Background(), nodeClient, &IPInfo{IP: "8.8.8.8"})
	if *p.PurityScore != 80 || !p.Flags["vpn"] || !p.Cached {
		t.Fatal("cache shares mutable score")
	}
	data, _ := json.Marshal(p)
	if strings.Contains(string(data), cfg.ProxycheckKey) {
		t.Fatal("key leaked to result")
	}
}

func TestReputationUnavailableAndBudget(t *testing.T) {
	for _, v := range []struct {
		status     int
		body, want string
	}{{403, "forbidden", "http_error"}, {429, "quota", "rate_limited"}, {302, "redirect", "http_error"}, {200, "{}", "invalid_response"}, {200, strings.Repeat("x", 65537), "invalid_response"}} {
		checker := NewReputationChecker(config.Defaults())
		checker.client.Transport = reputationTransport(func(*http.Request) (*http.Response, error) { return reputationResponse(v.status, v.body), nil })
		p := checker.Analyze(context.Background(), nil, &IPInfo{IP: "8.8.8.8"})
		if p.Verified || p.PurityScore != nil || p.FraudScore != nil || p.Status != v.want {
			t.Fatal("HTTP failure became a rating", p)
		}
	}
	cfg := config.Defaults()
	cfg.ProxycheckKey = "test-only-secret"
	cfg.ReputationDailyLimit = 1
	checker := NewReputationChecker(cfg)
	checker.client.Transport = reputationTransport(func(req *http.Request) (*http.Response, error) { return nil, fmt.Errorf("request URL %s", req.URL) })
	p := checker.Analyze(context.Background(), nil, &IPInfo{IP: "8.8.8.8"})
	if p.Status != "network_error" || strings.Contains(p.Reason, cfg.ProxycheckKey) {
		t.Fatal("network error leaked URL key")
	}
	checker.rateMu.Lock()
	checker.next = time.Time{}
	checker.rateMu.Unlock()
	if p = checker.Analyze(context.Background(), nil, &IPInfo{IP: "1.1.1.1"}); p.Status != "daily_limit" || p.Verified {
		t.Fatal("daily budget bypassed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	checker = NewReputationChecker(config.Defaults())
	p = checker.Analyze(ctx, nil, &IPInfo{IP: "8.8.8.8"})
	if p.Status != "timeout" || checker.used != 0 {
		t.Fatal("canceled request spent budget")
	}
	cfg.ReputationProvider = "off"
	checker = NewReputationChecker(cfg)
	if p = checker.Analyze(context.Background(), nil, &IPInfo{IP: "8.8.8.8"}); p.Verified || p.Status != "disabled" || checker.used != 0 {
		t.Fatal("off queried")
	}
}

func TestIPPureUsesNodeTransport(t *testing.T) {
	cfg := config.Defaults()
	cfg.ReputationProvider = "ippure"
	checker := NewReputationChecker(cfg)
	checker.client.Transport = reputationTransport(func(*http.Request) (*http.Response, error) {
		t.Error("IPPure used server exit")
		return nil, errors.New("unexpected")
	})
	nodeClient := &http.Client{Transport: reputationTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://my.ippure.com/v1/info" {
			t.Error("wrong provider URL")
		}
		return reputationResponse(200, `{"ip":"8.8.8.8","fraudScore":50}`), nil
	})}
	p := checker.Analyze(context.Background(), nodeClient, &IPInfo{IP: "8.8.8.8"})
	if !p.Verified || *p.FraudScore != 50 || p.Source != "IPPure" {
		t.Fatal("wrong node-provider result", p)
	}
}
