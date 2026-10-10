package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/2089887529/NodePure/pkg/config"
)

func TestKernelTempOverrideAndFallback(t *testing.T) {
	old := config.Global
	config.Global = config.Defaults()
	t.Cleanup(func() { config.Global = old })
	root := t.TempDir()
	config.Global.TempDir = root
	dir, e := makeKernelTemp()
	if e != nil || filepath.Dir(dir) != root {
		t.Fatalf("explicit private directory: %v", e)
	}
	os.RemoveAll(dir)
	config.Global.TempDir = filepath.Join(root, "missing")
	if _, e = makeKernelTemp(); e == nil {
		t.Fatal("explicit invalid directory silently replaced")
	}
	config.Global.TempDir = ""
	invalidTemp := filepath.Join(root, "not-a-directory")
	if e = os.WriteFile(invalidTemp, []byte("test"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, env := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(env, invalidTemp)
	}
	t.Setenv("XDG_CACHE_HOME", root)
	t.Setenv("LOCALAPPDATA", root)
	dir, e = makeKernelTemp()
	if e != nil {
		t.Fatalf("OS temporary directory fallback: %v", e)
	}
	defer os.RemoveAll(dir)
	cache, e := os.UserCacheDir()
	if e != nil || filepath.Dir(dir) != filepath.Join(cache, "NodePure", "tmp") {
		t.Fatal("fallback used unexpected directory")
	}
}
