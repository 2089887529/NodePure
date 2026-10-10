package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeConfiguration(t *testing.T) {
	for _, name := range []string{"NODEPURE_HOST", "NODEPURE_PORT", "MAX_CONCURRENCY", "MAX_NODES", "MAX_TASKS", "MAX_ACTIVE_TASKS", "QUEUE_SIZE", "MIHOMO_BIN", "MIHOMO_SHA256", "NODEPURE_PASSWORD_HASH_FILE", "NODEPURE_ALLOWED_HOSTS", "NODEPURE_PUBLIC_ORIGIN", "SUBSCRIPTION_ALLOWLIST"} {
		t.Setenv(name, "")
	}
	old := Global
	t.Cleanup(func() { Global = old })
	cfg, e := Load()
	if e != nil || cfg.Host != "127.0.0.1" {
		t.Fatal("unsafe defaults", e)
	}
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
