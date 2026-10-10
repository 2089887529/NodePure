package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Host                                                          string
	Port                                                          int
	MihomoBin, MihomoSHA256, PasswordHash, PublicOrigin, TempDir  string
	AllowedHosts, SubscriptionAllowlist                           []string
	MaxConcurrency, MaxNodes, MaxTasks, MaxActiveTasks, QueueSize int
	MaxBodyBytes                                                  int64
	TaskTimeout, TaskTTL                                          time.Duration
}

func Defaults() *Config {
	return &Config{Host: "127.0.0.1", Port: 8099, MihomoBin: "./bin/mihomo", MaxConcurrency: 20, MaxNodes: 500, MaxTasks: 50, MaxActiveTasks: 2, QueueSize: 4, MaxBodyBytes: 2 << 20, TaskTimeout: 20 * time.Minute, TaskTTL: time.Hour}
}

var Global = Defaults()

func Load() (*Config, error) {
	c := Defaults()
	if s := os.Getenv("NODEPURE_HOST"); s != "" {
		c.Host = s
	}
	for _, v := range []struct {
		name   string
		p      *int
		lo, hi int
	}{{"NODEPURE_PORT", &c.Port, 1, 65535}, {"MAX_CONCURRENCY", &c.MaxConcurrency, 1, 64}, {"MAX_NODES", &c.MaxNodes, 1, 1000}, {"MAX_TASKS", &c.MaxTasks, 1, 200}, {"MAX_ACTIVE_TASKS", &c.MaxActiveTasks, 1, 4}, {"QUEUE_SIZE", &c.QueueSize, 1, 20}} {
		if s := os.Getenv(v.name); s != "" {
			n, e := strconv.Atoi(s)
			if e != nil || n < v.lo || n > v.hi {
				return nil, fmt.Errorf("%s must be between %d and %d", v.name, v.lo, v.hi)
			}
			*v.p = n
		}
	}
	if s := os.Getenv("MIHOMO_BIN"); s != "" {
		c.MihomoBin = s
	}
	c.MihomoSHA256 = os.Getenv("MIHOMO_SHA256")
	c.TempDir = os.Getenv("NODEPURE_TEMP_DIR")
	c.PublicOrigin = os.Getenv("NODEPURE_PUBLIC_ORIGIN")
	if path := os.Getenv("NODEPURE_PASSWORD_HASH_FILE"); path != "" {
		b, e := os.ReadFile(path)
		if e != nil {
			return nil, fmt.Errorf("cannot read password hash file")
		}
		c.PasswordHash = strings.TrimSpace(string(b))
	}
	ip := net.ParseIP(c.Host)
	if ip == nil && c.Host != "localhost" {
		return nil, fmt.Errorf("NODEPURE_HOST must be localhost or an IP address")
	}
	if c.Host != "localhost" && !ip.IsLoopback() && c.PasswordHash == "" {
		return nil, fmt.Errorf("LAN access requires NODEPURE_PASSWORD_HASH_FILE")
	}
	if s := os.Getenv("NODEPURE_ALLOWED_HOSTS"); s != "" {
		c.AllowedHosts = strings.Split(s, ",")
	}
	if s := os.Getenv("SUBSCRIPTION_ALLOWLIST"); s != "" {
		c.SubscriptionAllowlist = strings.Split(s, ",")
	}
	Global = c
	return c, nil
}
