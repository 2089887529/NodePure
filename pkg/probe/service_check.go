package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

type ServiceStatus struct {
	ChatGPT string `json:"chatgpt"`
	Claude  string `json:"claude"`
	YouTube string `json:"youtube"`
	Google  string `json:"google"`
	Scope   string `json:"scope"`
}
type LatencyMetrics struct {
	HandshakeRTT int    `json:"handshake_rtt"`
	HTTPRTT      int    `json:"http_rtt"`
	TLSRTT       int    `json:"tls_rtt"`
	Source       string `json:"source"`
}

func webStatus(ctx context.Context, client *http.Client, address string, expected int) string {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "GET", address, nil)
	if e != nil {
		return "error"
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 NodePure/1.1")
	resp, e := client.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return "timeout"
		}
		return "error"
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == expected {
		return "ok"
	}
	if resp.StatusCode == 429 {
		return "rate_limited"
	}
	if resp.StatusCode == 403 || resp.StatusCode == 451 {
		return "restricted"
	}
	return "error"
}
func latency(ctx context.Context, client *http.Client, address string) *LatencyMetrics {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	m := &LatencyMetrics{HTTPRTT: -1, HandshakeRTT: -1, TLSRTT: -1, Source: address}
	var mu sync.Mutex
	var connectStart, tlsStart time.Time
	trace := &httptrace.ClientTrace{ConnectStart: func(_, _ string) { mu.Lock(); connectStart = time.Now(); mu.Unlock() }, ConnectDone: func(_, _ string, e error) {
		mu.Lock()
		defer mu.Unlock()
		if e == nil && !connectStart.IsZero() {
			m.HandshakeRTT = int(time.Since(connectStart).Milliseconds())
		}
	}, TLSHandshakeStart: func() { mu.Lock(); tlsStart = time.Now(); mu.Unlock() }, TLSHandshakeDone: func(_ tls.ConnectionState, e error) {
		mu.Lock()
		defer mu.Unlock()
		if e == nil && !tlsStart.IsZero() {
			m.TLSRTT = int(time.Since(tlsStart).Milliseconds())
		}
	}}
	req, e := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", address, nil)
	if e != nil {
		return m
	}
	start := time.Now()
	resp, e := client.Do(req)
	if e == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 204 {
			mu.Lock()
			m.HTTPRTT = int(time.Since(start).Milliseconds())
			mu.Unlock()
		}
	}
	mu.Lock()
	copy := *m
	mu.Unlock()
	return &copy
}
func CheckServices(ctx context.Context, client *http.Client) (*ServiceStatus, *LatencyMetrics) {
	status := &ServiceStatus{Scope: "web_connectivity_only"}
	type answer struct {
		which, value string
		metric       *LatencyMetrics
	}
	results := make(chan answer, 5)
	endpoints := map[string]string{"chatgpt": "https://chatgpt.com/", "claude": "https://claude.ai/", "youtube": "https://www.youtube.com/premium", "google": "https://www.gstatic.com/generate_204"}
	for name, address := range endpoints {
		go func(which, url string) {
			expected := 200
			if which == "google" {
				expected = 204
			}
			results <- answer{which: which, value: webStatus(ctx, client, url, expected)}
		}(name, address)
	}
	go func() {
		m := latency(ctx, client, "https://www.cloudflare.com/cdn-cgi/generate_204")
		if m.HTTPRTT < 0 && ctx.Err() == nil {
			m = latency(ctx, client, "https://www.gstatic.com/generate_204")
		}
		results <- answer{which: "latency", metric: m}
	}()
	var metric *LatencyMetrics
	for i := 0; i < 5; i++ {
		a := <-results
		switch a.which {
		case "chatgpt":
			status.ChatGPT = a.value
		case "claude":
			status.Claude = a.value
		case "youtube":
			status.YouTube = a.value
		case "google":
			status.Google = a.value
		case "latency":
			metric = a.metric
		}
	}
	return status, metric
}
