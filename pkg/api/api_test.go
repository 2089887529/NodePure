package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/2089887529/NodePure/pkg/config"
	"github.com/2089887529/NodePure/pkg/core"
	"github.com/2089887529/NodePure/pkg/probe"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testServer(t *testing.T, runner Runner) (*Server, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := config.Defaults()
	s, e := NewServer(cfg, runner)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Manager.Close)
	r := gin.New()
	s.Register(r)
	return s, r
}
func apiRequest(r http.Handler, method, path, body string, cookie *http.Cookie, header bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if header {
		req.Header.Set("X-NodePure", "1")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
func testSession(t *testing.T, r http.Handler) *http.Cookie {
	t.Helper()
	w := apiRequest(r, "GET", "/api/auth/session", "", nil, false)
	cs := w.Result().Cookies()
	if w.Code != 200 || len(cs) != 1 || !cs[0].HttpOnly || cs[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("bad session %d", w.Code)
	}
	return cs[0]
}
func awaitTask(t *testing.T, task *Task) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if terminal(task.snapshot(false).Status) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("task did not terminate")
}
func TestAuthOwnershipAndPrivacy(t *testing.T) {
	run := func(_ context.Context, ns []*core.ProxyNode, _ int, emit func(*probe.ProbeResult)) error {
		for _, n := range ns {
			emit(&probe.ProbeResult{NodeID: n.ID, NodeName: n.Name, Success: true, RawConfig: n.RawConfig, Purity: probe.AnalyzePurity(nil)})
		}
		return nil
	}
	s, r := testServer(t, run)
	a := testSession(t, r)
	b := testSession(t, r)
	if apiRequest(r, "GET", "/api/tasks", "", nil, false).Code != 401 {
		t.Fatal("anonymous API accepted")
	}
	if apiRequest(r, "POST", "/api/check", "{}", a, false).Code != 403 {
		t.Fatal("missing CSRF header accepted")
	}
	req := httptest.NewRequest("GET", "http://evil.example/api/auth/session", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("DNS rebinding host accepted")
	}
	req = httptest.NewRequest("POST", "http://localhost/api/check", strings.NewReader("{}"))
	req.Header.Set("X-NodePure", "1")
	req.Header.Set("Origin", "https://evil.example")
	req.AddCookie(a)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("cross origin accepted")
	}
	content := `proxies:
  - {name: '=HYPERLINK("bad")', type: http, server: example.com, port: 443, password: private-node-password}
`
	payload, _ := json.Marshal(map[string]any{"content": content, "concurrency": 999999})
	w = apiRequest(r, "POST", "/api/check", string(payload), a, true)
	var resp struct {
		TaskID      string `json:"task_id"`
		Concurrency int    `json:"concurrency"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != 200 || resp.Concurrency != s.cfg.MaxConcurrency {
		t.Fatalf("limits failed %d %s", w.Code, w.Body)
	}
	ownerKey := s.Auth.sessionsKeyForTest(a.Value)
	task, ok := s.Manager.lookup(resp.TaskID, ownerKey)
	if !ok {
		t.Fatal("missing task")
	}
	awaitTask(t, task)
	for _, path := range []string{"/api/task/", "/api/stream/", "/api/export/csv/"} {
		if apiRequest(r, "GET", path+resp.TaskID, "", b, false).Code != 404 {
			t.Fatal("other browser can read task", path)
		}
	}
	for _, path := range []string{"/api/task/", "/api/stream/"} {
		w = apiRequest(r, "GET", path+resp.TaskID, "", a, false)
		if w.Code != 200 || strings.Contains(w.Body.String(), "private-node-password") || strings.Contains(w.Body.String(), "raw_config") {
			t.Fatal("result leaked config", path)
		}
	}
	w = apiRequest(r, "GET", "/api/tasks", "", b, false)
	if strings.Contains(w.Body.String(), resp.TaskID) {
		t.Fatal("task listing leak")
	}
	w = apiRequest(r, "GET", "/api/export/csv/"+resp.TaskID, "", a, false)
	if !strings.Contains(w.Body.String(), "'=HYPERLINK") {
		t.Fatal("CSV formula not neutralized", w.Body)
	}
	payload, _ = json.Marshal(map[string]any{"task_id": resp.TaskID, "min_score": 80})
	if apiRequest(r, "POST", "/api/export/clash", string(payload), a, true).Code != 400 {
		t.Fatal("unknown risk passed filter")
	}
	payload, _ = json.Marshal(map[string]any{"task_id": resp.TaskID})
	w = apiRequest(r, "POST", "/api/export/clash", string(payload), a, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "private-node-password") {
		t.Fatal("authorized explicit export failed")
	}
	apiRequest(r, "POST", "/api/auth/logout", "{}", a, true)
	if apiRequest(r, "GET", "/api/tasks", "", a, false).Code != 401 {
		t.Fatal("logout did not revoke session")
	}
}
func (a *Auth) sessionsKeyForTest(token string) string {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.AddCookie(&http.Cookie{Name: "nodepure_session", Value: token})
	o, _ := a.owner(c)
	return o
}
func TestReplayBeyondFiftyAndResume(t *testing.T) {
	s, r := testServer(t, func(context.Context, []*core.ProxyNode, int, func(*probe.ProbeResult)) error { return nil })
	cookie := testSession(t, r)
	task := &Task{Owner: s.Auth.sessionsKeyForTest(cookie.Value), state: TaskSnapshot{ID: "replay", Status: "running", Total: 200}, notify: make(chan struct{})}
	s.Manager.mu.Lock()
	s.Manager.tasks["replay"] = task
	s.Manager.mu.Unlock()
	for i := 0; i < 200; i++ {
		task.publish(&probe.ProbeResult{NodeID: fmt.Sprint(i)}, "", "")
	}
	task.publish(nil, "completed", "")
	for _, after := range []int{0, 50, 199, 201} {
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			done <- apiRequest(r, "GET", fmt.Sprintf("/api/stream/replay?after=%d", after), "", cookie, false)
		}()
		select {
		case w := <-done:
			if w.Code != 200 || strings.Count(w.Body.String(), "event: message") != 201-after {
				t.Fatalf("lost replay %d %d", after, w.Code)
			}
		case <-time.After(time.Second):
			t.Fatal("replay deadlocked")
		}
	}
	if apiRequest(r, "GET", "/api/stream/replay?after=999", "", cookie, false).Code != 400 {
		t.Fatal("invalid cursor accepted")
	}
	// Close only calls cancel for managed tasks.
	s.Manager.mu.Lock()
	delete(s.Manager.tasks, "replay")
	s.Manager.mu.Unlock()
}
func TestConcurrentListCancelAndCapacity(t *testing.T) {
	entered := make(chan struct{}, 1)
	s, _ := testServer(t, func(ctx context.Context, _ []*core.ProxyNode, _ int, _ func(*probe.ProbeResult)) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	})
	task, e := s.Manager.Add("owner", []*core.ProxyNode{{ID: "n"}}, nil, 100)
	if e != nil {
		t.Fatal(e)
	}
	<-entered
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.Manager.list("owner")
				task.snapshot(true)
			}
		}()
	}
	for i := 1; i < s.cfg.MaxActiveTasks+s.cfg.QueueSize; i++ {
		if _, e = s.Manager.Add("owner", []*core.ProxyNode{{ID: fmt.Sprint(i)}}, nil, 1); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = s.Manager.Add("owner", nil, nil, 1); e == nil {
		t.Fatal("unbounded tasks")
	}
	task.cancel()
	task.publish(nil, "canceled", "")
	wg.Wait()
	task.mu.Lock()
	task.state.FinishedAt = time.Now().Add(-2 * s.cfg.TaskTTL)
	task.mu.Unlock()
	s.Manager.mu.Lock()
	s.Manager.pruneLocked()
	s.Manager.mu.Unlock()
	if _, ok := s.Manager.lookup(task.state.ID, "owner"); ok {
		t.Fatal("expired task retained")
	}
}
func TestPasswordRequiredAndRateLimit(t *testing.T) {
	cfg := config.Defaults()
	cfg.Host = "0.0.0.0"
	if _, e := NewAuth(cfg); e == nil {
		t.Fatal("LAN allowed without password")
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("test-password-only"), bcrypt.MinCost)
	cfg.PasswordHash = string(hash)
	a, e := NewAuth(cfg)
	if e != nil {
		t.Fatal(e)
	}
	r := gin.New()
	r.Use(a.security)
	a.register(r)
	for i := 0; i < 11; i++ {
		w := apiRequest(r, "POST", "/api/auth/login", `{"password":"wrong"}`, nil, true)
		want := 401
		if i == 10 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("rate limit %d=%d", i, w.Code)
		}
	}
	a.mu.Lock()
	a.attempts = map[string]attempt{}
	a.mu.Unlock()
	w := apiRequest(r, "POST", "/api/auth/login", `{"password":"test-password-only"}`, nil, true)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatal("login failed")
	}
	w = apiRequest(r, "GET", "/api/auth/session", "", nil, false)
	if bytes.Contains(w.Body.Bytes(), []byte(`"authenticated":true`)) {
		t.Fatal("LAN anonymous session")
	}
}
