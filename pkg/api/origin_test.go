package api

import (
	"github.com/2089887529/NodePure/pkg/config"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPSProxyOriginAndSecureCookie(t *testing.T) {
	cfg := config.Defaults()
	cfg.PublicOrigin = "https://nodes.example.com"
	if _, e := NewAuth(cfg); e == nil {
		t.Fatal("anonymous HTTPS proxy deployment")
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("test-proxy-password"), bcrypt.MinCost)
	cfg.PasswordHash = string(hash)
	a, e := NewAuth(cfg)
	if e != nil {
		t.Fatal(e)
	}
	r := gin.New()
	r.Use(a.security)
	a.register(r)
	req := httptest.NewRequest("POST", "http://nodes.example.com/api/auth/login", strings.NewReader(`{"password":"test-proxy-password"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NodePure", "1")
	req.Header.Set("Origin", "https://nodes.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 || !w.Result().Cookies()[0].Secure {
		t.Fatal("HTTPS origin/cookie failed", w.Code)
	}
	req = httptest.NewRequest("GET", "http://nodes.example.com/api/auth/session", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("X-Forwarded-Host", "nodes.example.com")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("forwarded header bypass")
	}
	for _, bad := range []string{"http://nodes.example.com", "https://nodes.example.com/path", "https://user@nodes.example.com"} {
		cfg.PublicOrigin = bad
		if _, e := NewAuth(cfg); e == nil {
			t.Fatal("invalid origin", bad)
		}
	}
}
