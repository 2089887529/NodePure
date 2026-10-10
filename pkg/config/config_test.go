package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeConfiguration(t *testing.T) {
	for _, name := range []string{"NODEPURE_HOST", "NODEPURE_PORT", "MAX_CONCURRENCY", "MAX_NODES", "MAX_TASKS", "MAX_ACTIVE_TASKS", "QUEUE_SIZE", "MIHOMO_BIN", "MIHOMO_SHA256", "NODEPURE_PASSWORD_HASH_FILE", "NODEPURE_ALLOWED_HOSTS", "NODEPURE_PUBLIC_ORIGIN", "SUBSCRIPTION_ALLOWLIST", "REPUTATION_PROVIDER", "PROXYCHECK_API_KEY", "PROXYCHECK_API_KEY_FILE", "REPUTATION_DAILY_LIMIT"} {
		t.Setenv(name, "")
	}
	old := Global
	t.Cleanup(func() { Global = old })
	cfg, e := Load()
	if e != nil || cfg.Host != "127.0.0.1" {
		t.Fatal("unsafe defaults", e)
	}
	if cfg.ReputationProvider != "proxycheck" || cfg.ReputationDailyLimit != 100 {
		t.Fatal("scoring defaults")
	}
	t.Setenv("REPUTATION_PROVIDER", "invalid")
	if _, e = Load(); e == nil {
		t.Fatal("bad provider accepted")
	}
	t.Setenv("REPUTATION_PROVIDER", "")
	t.Setenv("REPUTATION_DAILY_LIMIT", "0")
	if _, e = Load(); e == nil {
		t.Fatal("bad score budget accepted")
	}
	t.Setenv("REPUTATION_DAILY_LIMIT", "")
	keyFile := filepath.Join(t.TempDir(), "provider.key")
	os.WriteFile(keyFile, []byte("test-key\n"), 0600)
	t.Setenv("PROXYCHECK_API_KEY_FILE", keyFile)
	cfg, e = Load()
	if e != nil || cfg.ProxycheckKey != "test-key" || cfg.ReputationDailyLimit != 1000 {
		t.Fatal("key file", e)
	}
	t.Setenv("PROXYCHECK_API_KEY", "another-test-key")
	if _, e = Load(); e == nil {
		t.Fatal("ambiguous key source accepted")
	}
	t.Setenv("PROXYCHECK_API_KEY", "")
	t.Setenv("PROXYCHECK_API_KEY_FILE", "")
	t.Setenv("NODEPURE_HOST", "0.0.0.0")
	if _, e = Load(); e == nil {
		t.Fatal("anonymous LAN")
	}
	t.Setenv("NODEPURE_HOST", "127.0.0.1")
	for _, field := range []string{"NODEPURE_PORT", "MAX_CONCURRENCY", "MAX_NODES", "MAX_TASKS", "MAX_ACTIVE_TASKS", "QUEUE_SIZE"} {
		t.Setenv(field, "9999999")
		if _, e = Load(); e == nil {
			t.Fatal("invalid limit accepted", field)
		}
		t.Setenv(field, "")
	}
	hashFile := filepath.Join(t.TempDir(), "password.hash")
	os.WriteFile(hashFile, []byte("hash-for-config-test"), 0600)
	t.Setenv("NODEPURE_PASSWORD_HASH_FILE", hashFile)
	t.Setenv("NODEPURE_HOST", "::")
	cfg, e = Load()
	if e != nil || cfg.PasswordHash != "hash-for-config-test" {
		t.Fatal("password file", e)
	}
}
