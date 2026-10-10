package main

import (
	"context"
	"fmt"
	"github.com/2089887529/NodePure/pkg/api"
	"github.com/2089887529/NodePure/pkg/config"
	"github.com/2089887529/NodePure/web"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--set-password" {
		if e := setPassword(os.Args[2]); e != nil {
			log.Fatal(e)
		}
		return
	}
	cfg, e := config.Load()
	if e != nil {
		log.Fatal(e)
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.SetTrustedProxies(nil)
	server, e := api.NewServer(cfg, nil)
	if e != nil {
		log.Fatal(e)
	}
	defer server.Manager.Close()
	server.Register(r)
	files := http.FileServer(web.GetFileSystem())
	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(404, gin.H{"error": "endpoint not found"})
			return
		}
		files.ServeHTTP(c.Writer, c.Request)
	})
	httpServer := &http.Server{Addr: net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port)), Handler: api.HTTPHandler(r), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 25 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		httpServer.Shutdown(ctx)
	}()
	fmt.Printf("NodePure listening on http://%s (web connectivity; risk measurements unknown without a verified source)\n", httpServer.Addr)
	if e = httpServer.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		log.Print(e)
		os.Exit(1)
	}
}

// Accept a password only through a pipe. Never accept it in argv or print it.
func setPassword(path string) error {
	st, e := os.Stdin.Stat()
	if e != nil {
		return e
	}
	if st.Mode()&os.ModeCharDevice != 0 {
		return fmt.Errorf("pipe a password from a hidden prompt; terminal echo is not allowed")
	}
	b, e := io.ReadAll(io.LimitReader(os.Stdin, 74))
	if e != nil {
		return e
	}
	password := strings.TrimRight(string(b), "\r\n")
	if len(password) < 12 || len(password) > 72 {
		return fmt.Errorf("password must be 12–72 bytes")
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return fmt.Errorf("create a new hash file; existing files are never overwritten")
	}
	defer f.Close()
	if _, e = f.Write(hash); e != nil {
		return e
	}
	return f.Sync()
}
