package core

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestProtocols(t *testing.T) {
	uuid := "00000000-0000-4000-8000-000000000001"
	vmess := base64.StdEncoding.EncodeToString([]byte(`{"ps":"vmess demo","add":"example.org","port":"443","id":"` + uuid + `","aid":"0","net":"ws","host":"example.org","path":"/ws","tls":"tls","sni":"example.org"}`))
	ss := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:synthetic-pass"))
	cases := []struct {
		uri, kind, key string
		value          interface{}
	}{
		{"http://demo:synthetic@127.0.0.1:8080#http", "http", "password", "synthetic"},
		{"socks5://demo:synthetic@127.0.0.1:1080#socks", "socks5", "username", "demo"},
		{"ss://" + ss + "@example.org:443#SS", "ss", "cipher", "aes-128-gcm"},
		{"ss://aes-128-gcm:synthetic@example.org:443", "ss", "password", "synthetic"},
		{"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:synthetic#/@pass@example.org:443")), "ss", "password", "synthetic#/@pass"},
		{"trojan://synthetic@example.org:443?sni=example.org&type=ws&path=%2Fws", "trojan", "sni", "example.org"},
		{"vless://" + uuid + "@example.org:443?security=reality&sni=example.org&pbk=synthetic&sid=1234&type=grpc&serviceName=demo", "vless", "network", "grpc"},
		{"hy2://synthetic@example.org:443?sni=example.org&obfs=salamander&obfs-password=synthetic", "hysteria2", "obfs", "salamander"},
		{"vmess://" + vmess, "vmess", "network", "ws"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			nodes, e := ParseNodes(tc.uri)
			if e != nil || len(nodes) != 1 {
				t.Fatal(e)
			}
			p := nodes[0].RawConfig
			if p["type"] != tc.kind || p[tc.key] != tc.value {
				t.Fatalf("incorrect %s mapping", tc.kind)
			}
		})
	}
}
func TestParseWarningsAndLimits(t *testing.T) {
	input := "proxies:\n- {name: A, type: ss, server: example.org, port: 443}\n- {name: A, type: ss, server: example.org, port: 443}\n- {name: 'A #2', type: ss, server: example.org, port: 443}\n- {name: invalid, type: ss, server: example.org, port: 999999}\n"
	nodes, w, e := ParseNodesDetailed(input, 10)
	if e != nil || len(nodes) != 3 || len(w) != 1 {
		t.Fatal(e)
	}
	names := map[string]bool{}
	for _, n := range nodes {
		if names[n.Name] {
			t.Fatal("duplicate")
		}
		names[n.Name] = true
	}
	if _, _, e = ParseNodesDetailed(input, 2); e == nil {
		t.Fatal("node limit ignored")
	}
	if _, _, e = ParseNodesDetailed(strings.Repeat("x", (2<<20)+1), 100); e == nil {
		t.Fatal("body limit ignored")
	}
	if _, e = ParseNodes("trojan://example.org:443"); e == nil {
		t.Fatal("missing credentials accepted")
	}
	if _, e = ParseNodes("vless://demo@example.org:443?type=unsupported"); e == nil {
		t.Fatal("unsupported transport silently accepted")
	}
	nodes, w, e = ParseNodesDetailed("unknown://secret@example.org:443\nhttp://example.org:8080", 10)
	if e != nil || len(nodes) != 1 || len(w) != 1 || strings.Contains(w[0].Reason, "secret") {
		t.Fatal("warnings incorrect")
	}
}
func TestRestrictedAddresses(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "192.168.1.1", "100.64.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "fc00::1", "2001:db8::1", "64:ff9b::7f00:1", "100::1", "2001:2::1", "3fff::1", "5f00::1"} {
		if publicAddress(netip.MustParseAddr(s)) {
			t.Fatal("accepted", s)
		}
	}
	if !publicAddress(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public rejected")
	}
}
func TestFetchPolicyAndSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("x", 100)) }))
	defer server.Close()
	if _, e := FetchSubscriptionContext(context.Background(), server.URL, SubscriptionPolicy{}); e == nil {
		t.Fatal("loopback accepted")
	}
	if _, e := FetchSubscriptionContext(context.Background(), server.URL, SubscriptionPolicy{Allowlist: []string{"127.0.0.1"}, MaxBytes: 10}); e == nil {
		t.Fatal("response size ignored")
	}
	if b, e := FetchSubscriptionContext(context.Background(), server.URL, SubscriptionPolicy{Allowlist: []string{"127.0.0.1"}, MaxBytes: 200}); e != nil || len(b) != 100 {
		t.Fatal("explicit allowlist unusable", e)
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://[::1]:9999/", 302) }))
	defer redirect.Close()
	if _, e := FetchSubscriptionContext(context.Background(), redirect.URL, SubscriptionPolicy{Allowlist: []string{"127.0.0.1"}}); e == nil {
		t.Fatal("redirect destination not validated")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := FetchSubscriptionContext(ctx, server.URL, SubscriptionPolicy{Allowlist: []string{"127.0.0.1"}}); e == nil {
		t.Fatal("cancellation ignored")
	}
	for _, url := range []string{"file:///etc/passwd", "http://user:secret@8.8.8.8/"} {
		if _, e := FetchSubscriptionContext(context.Background(), url, SubscriptionPolicy{}); e == nil {
			t.Fatal("invalid URL accepted")
		}
	}
}
