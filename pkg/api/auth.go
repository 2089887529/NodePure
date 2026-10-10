package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/2089887529/NodePure/pkg/config"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type session struct {
	Owner   string
	Expires time.Time
}
type attempt struct {
	Count int
	Until time.Time
}
type Auth struct {
	cfg      *config.Config
	mu       sync.Mutex
	sessions map[[32]byte]session
	attempts map[string]attempt
	hosts    map[string]bool
}

func randomID() (string, error) {
	b := make([]byte, 24)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func NewAuth(cfg *config.Config) (*Auth, error) {
	ip := net.ParseIP(cfg.Host)
	if ((cfg.Host != "localhost" && (ip == nil || !ip.IsLoopback())) || cfg.PublicOrigin != "") && cfg.PasswordHash == "" {
		return nil, fmt.Errorf("non-loopback access requires a password hash")
	}
	if cfg.PasswordHash != "" {
		if cost, e := bcrypt.Cost([]byte(cfg.PasswordHash)); e != nil || cost > 14 {
			return nil, fmt.Errorf("invalid/unsupported bcrypt password hash")
		}
	}
	a := &Auth{cfg: cfg, sessions: map[[32]byte]session{}, attempts: map[string]attempt{}, hosts: map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}}
	if cfg.PublicOrigin != "" {
		u, e := url.Parse(cfg.PublicOrigin)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("NODEPURE_PUBLIC_ORIGIN must be an HTTPS origin")
		}
		cfg.PublicOrigin = strings.TrimSuffix(cfg.PublicOrigin, "/")
		a.hosts[strings.ToLower(u.Hostname())] = true
	}
	if cfg.Host != "0.0.0.0" && cfg.Host != "::" {
		a.hosts[strings.ToLower(cfg.Host)] = true
	} else {
		addresses, _ := net.InterfaceAddrs()
		for _, address := range addresses {
			ip, _, e := net.ParseCIDR(address.String())
			if e == nil {
				a.hosts[ip.String()] = true
			}
		}
	}
	for _, host := range cfg.AllowedHosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || strings.ContainsAny(host, "/* ") {
			return nil, fmt.Errorf("invalid allowed host")
		}
		a.hosts[host] = true
	}
	return a, nil
}
func (a *Auth) security(c *gin.Context) {
	host := c.Request.Host
	if h, _, e := net.SplitHostPort(host); e == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if !a.hosts[strings.ToLower(host)] {
		c.AbortWithStatusJSON(403, gin.H{"error": "host not allowed"})
		return
	}
	if origin := c.GetHeader("Origin"); origin != "" {
		u, e := url.Parse(origin)
		scheme := "http"
		if c.Request.TLS != nil {
			scheme = "https"
		}
		expected := scheme + "://" + c.Request.Host
		if a.cfg.PublicOrigin != "" {
			expected = a.cfg.PublicOrigin
		}
		if e != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Scheme+"://"+u.Host != expected {
			c.AbortWithStatusJSON(403, gin.H{"error": "cross-origin request denied"})
			return
		}
	}
	if c.GetHeader("Sec-Fetch-Site") == "cross-site" {
		c.AbortWithStatusJSON(403, gin.H{"error": "cross-site request denied"})
		return
	}
	if c.Request.Method != "GET" && c.Request.Method != "HEAD" && c.GetHeader("X-NodePure") != "1" {
		c.AbortWithStatusJSON(403, gin.H{"error": "X-NodePure header required"})
		return
	}
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if strings.HasPrefix(c.Request.URL.Path, "/api/") {
		c.Header("Cache-Control", "no-store")
	}
	c.Next()
}
func (a *Auth) owner(c *gin.Context) (string, bool) {
	cookie, e := c.Cookie("nodepure_session")
	if e != nil {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	key := sha256.Sum256([]byte(cookie))
	s, ok := a.sessions[key]
	if !ok || time.Now().After(s.Expires) {
		delete(a.sessions, key)
		return "", false
	}
	return s.Owner, true
}
func (a *Auth) issue(c *gin.Context) error {
	token, e := randomID()
	if e != nil {
		return e
	}
	owner, e := randomID()
	if e != nil {
		return e
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, s := range a.sessions {
		if time.Now().After(s.Expires) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= 1024 {
		return fmt.Errorf("session limit reached")
	}
	a.sessions[sha256.Sum256([]byte(token))] = session{owner, time.Now().Add(24 * time.Hour)}
	http.SetCookie(c.Writer, &http.Cookie{Name: "nodepure_session", Value: token, Path: "/api", HttpOnly: true, Secure: c.Request.TLS != nil || a.cfg.PublicOrigin != "", SameSite: http.SameSiteStrictMode, MaxAge: 86400})
	return nil
}
func (a *Auth) require(c *gin.Context) {
	owner, ok := a.owner(c)
	if !ok {
		c.AbortWithStatusJSON(401, gin.H{"error": "authentication required"})
		return
	}
	c.Set("owner", owner)
	c.Next()
}
func (a *Auth) register(r *gin.Engine) {
	r.GET("/api/auth/session", func(c *gin.Context) {
		_, ok := a.owner(c)
		if !ok && a.cfg.PasswordHash == "" {
			if e := a.issue(c); e != nil {
				c.JSON(429, gin.H{"error": "session limit reached"})
				return
			}
			ok = true
		}
		c.JSON(200, gin.H{"authenticated": ok, "password_required": a.cfg.PasswordHash != "", "max_concurrency": a.cfg.MaxConcurrency, "max_nodes": a.cfg.MaxNodes})
	})
	r.POST("/api/auth/login", func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)
		var req struct {
			Password string `json:"password"`
		}
		if c.ShouldBindJSON(&req) != nil || len(req.Password) > 72 {
			c.JSON(400, gin.H{"error": "invalid login payload"})
			return
		}
		ip, _, _ := net.SplitHostPort(c.Request.RemoteAddr)
		a.mu.Lock()
		for k, v := range a.attempts {
			if time.Now().After(v.Until) {
				delete(a.attempts, k)
			}
		}
		v := a.attempts[ip]
		if time.Now().After(v.Until) {
			v = attempt{Until: time.Now().Add(time.Minute)}
		}
		v.Count++
		if len(a.attempts) < 4096 {
			a.attempts[ip] = v
		} else {
			v.Count = 11
		}
		a.mu.Unlock()
		if v.Count > 10 {
			c.JSON(429, gin.H{"error": "try again in one minute"})
			return
		}
		if a.cfg.PasswordHash == "" || bcrypt.CompareHashAndPassword([]byte(a.cfg.PasswordHash), []byte(req.Password)) != nil {
			c.JSON(401, gin.H{"error": "incorrect password"})
			return
		}
		if _, ok := a.owner(c); !ok {
			if e := a.issue(c); e != nil {
				c.JSON(429, gin.H{"error": "session limit reached"})
				return
			}
		}
		c.JSON(200, gin.H{"authenticated": true})
	})
	r.POST("/api/auth/logout", func(c *gin.Context) {
		cookie, _ := c.Cookie("nodepure_session")
		a.mu.Lock()
		delete(a.sessions, sha256.Sum256([]byte(cookie)))
		a.mu.Unlock()
		http.SetCookie(c.Writer, &http.Cookie{Name: "nodepure_session", Path: "/api", MaxAge: -1, HttpOnly: true, Secure: c.Request.TLS != nil || a.cfg.PublicOrigin != "", SameSite: http.SameSiteStrictMode})
		c.Status(204)
	})
}
