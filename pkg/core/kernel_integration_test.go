package core

import (
	"context"
	"fmt"
	"github.com/2089887529/NodePure/pkg/config"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestRealMihomoLifecycle(t *testing.T) {
	bin := os.Getenv("NODEPURE_TEST_MIHOMO")
	if bin == "" {
		t.Skip("set NODEPURE_TEST_MIHOMO to run real kernel integration")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Header.Get("Proxy-Authorization") != "Basic dGVzdC11c2VyOnRlc3Qtb25seQ==" {
			t.Error("upstream CONNECT authentication missing")
			w.WriteHeader(407)
			return
		}
		conn, rw, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error(e)
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		fmt.Fprint(rw, "HTTP/1.1 200 Connection established\r\n\r\n")
		rw.Flush()
		request, e := http.ReadRequest(rw.Reader)
		if e != nil {
			t.Error(e)
			return
		}
		request.Body.Close()
		fmt.Fprint(rw, "HTTP/1.1 200 OK\r\nContent-Length: 22\r\nConnection: close\r\n\r\nthrough-isolated-proxy")
		rw.Flush()
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	pn, _ := strconv.Atoi(port)
	ns, _, e := ParseNodesDetailed("proxies:\n  - {name: local-test, type: http, server: "+host+", port: "+port+", username: test-user, password: test-only}\n  - {name: invalid-test, type: invented, server: example.com, port: 443}\n", 10)
	if e != nil {
		t.Fatal(e)
	}
	if ns[0].Port != pn {
		t.Fatal("parse port")
	}
	old := config.Global
	cfg := config.Defaults()
	cfg.MihomoBin = bin
	config.Global = cfg
	defer func() { config.Global = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	k, e := StartKernelForNodes(ctx, ns)
	if e != nil {
		t.Fatal(e)
	}
	defer k.Stop()
	if len(k.Nodes) != 1 || len(k.Rejected) != 1 {
		t.Fatalf("node rejection mismatch valid=%d bad=%d", len(k.Nodes), len(k.Rejected))
	}
	node := k.Nodes[0]
	if ns[0].LocalPort != 0 {
		t.Fatal("original mutated")
	}
	p := &url.URL{Scheme: "socks5", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(node.LocalPort)), User: url.UserPassword(node.ProxyUser, node.ProxyPassword)}
	tr := &http.Transport{Proxy: http.ProxyURL(p)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	resp, e := client.Get("http://example.invalid/echo")
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "through-isolated-proxy" {
		t.Fatal("wrong upstream", string(b))
	}
	wrong := *p
	wrong.User = url.UserPassword("wrong", "wrong")
	bad := &http.Transport{Proxy: http.ProxyURL(&wrong)}
	defer bad.CloseIdleConnections()
	_, e = (&http.Client{Transport: bad, Timeout: time.Second}).Get("http://example.invalid/echo")
	if e == nil {
		t.Fatal("unauthenticated listener accepted")
	}
	dir := k.tempDir
	portAddr := p.Host
	st, e := os.Stat(dir + "/config.yaml")
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("config permissions")
	}
	k.Stop()
	select {
	case <-k.Done:
	default:
		t.Fatal("process not reaped")
	}
	if _, e = os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("temporary secrets retained")
	}
	if c, e := net.DialTimeout("tcp", portAddr, 200*time.Millisecond); e == nil {
		c.Close()
		t.Fatal("probe port still listening")
	}
}
