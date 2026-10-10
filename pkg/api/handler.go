package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/2089887529/NodePure/pkg/config"
	"github.com/2089887529/NodePure/pkg/core"
	"github.com/2089887529/NodePure/pkg/probe"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Server struct {
	Manager  *Manager
	Auth     *Auth
	cfg      *config.Config
	requests chan struct{}
}

func NewServer(cfg *config.Config, runner Runner) (*Server, error) {
	a, e := NewAuth(cfg)
	if e != nil {
		return nil, e
	}
	return &Server{Manager: NewManager(cfg, runner), Auth: a, cfg: cfg, requests: make(chan struct{}, cfg.MaxActiveTasks+cfg.QueueSize)}, nil
}
func (s *Server) Register(r *gin.Engine) {
	r.Use(s.Auth.security)
	s.Auth.register(r)
	a := r.Group("/api", s.Auth.require)
	a.POST("/check", s.check)
	a.GET("/tasks", s.list)
	a.GET("/task/:task_id", s.get)
	a.POST("/task/:task_id/cancel", s.cancelTask)
	a.DELETE("/task/:task_id", s.deleteTask)
	a.GET("/stream/:task_id", s.stream)
	a.POST("/export/clash", s.exportClash)
	a.GET("/export/csv/:task_id", s.exportCSV)
}
func owner(c *gin.Context) string { return c.GetString("owner") }
func (s *Server) find(c *gin.Context, id string) (*Task, bool) {
	t, ok := s.Manager.lookup(id, owner(c))
	if !ok {
		c.JSON(404, gin.H{"error": "task not found"})
	}
	return t, ok
}
func (s *Server) check(c *gin.Context) {
	select {
	case s.requests <- struct{}{}:
		defer func() { <-s.requests }()
	default:
		c.JSON(429, gin.H{"error": "too many incoming requests"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, s.cfg.MaxBodyBytes)
	var req struct {
		URL         string `json:"url"`
		Content     string `json:"content"`
		Concurrency int    `json:"concurrency"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(400, gin.H{"error": "invalid payload or input exceeds limit"})
		return
	}
	content := req.Content
	if content == "" && req.URL != "" {
		var e error
		content, e = core.FetchSubscriptionContext(c.Request.Context(), req.URL, core.SubscriptionPolicy{Allowlist: s.cfg.SubscriptionAllowlist, MaxBytes: s.cfg.MaxBodyBytes})
		if e != nil {
			c.JSON(400, gin.H{"error": e.Error()})
			return
		}
	}
	nodes, warnings, e := core.ParseNodesDetailed(content, s.cfg.MaxNodes)
	if e != nil {
		c.JSON(400, gin.H{"error": e.Error(), "warnings": warnings})
		return
	}
	t, e := s.Manager.Add(owner(c), nodes, warnings, req.Concurrency)
	if e != nil {
		c.JSON(429, gin.H{"error": e.Error()})
		return
	}
	state := t.snapshot(false)
	c.JSON(200, gin.H{"task_id": state.ID, "total_nodes": state.Total, "status": state.Status, "concurrency": t.concurrency, "warnings": warnings})
}
func (s *Server) get(c *gin.Context) {
	if t, ok := s.find(c, c.Param("task_id")); ok {
		c.JSON(200, t.snapshot(true))
	}
}
func (s *Server) list(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if page < 1 || limit < 1 || limit > 100 {
		c.JSON(400, gin.H{"error": "invalid pagination"})
		return
	}
	all := s.Manager.list(owner(c))
	start := (page - 1) * limit
	if start < 0 || start > len(all) {
		start = len(all)
	}
	end := start + limit
	if end > len(all) {
		end = len(all)
	}
	c.JSON(200, gin.H{"tasks": all[start:end], "total": len(all), "page": page})
}
func (s *Server) cancelTask(c *gin.Context) {
	if t, ok := s.find(c, c.Param("task_id")); ok {
		t.cancel()
		t.publish(nil, "canceled", "用户取消")
		c.JSON(200, t.snapshot(false))
	}
}
func (s *Server) deleteTask(c *gin.Context) {
	id := c.Param("task_id")
	t, ok := s.find(c, id)
	if !ok {
		return
	}
	if !terminal(t.snapshot(false).Status) {
		c.JSON(409, gin.H{"error": "cancel running task first"})
		return
	}
	s.Manager.mu.Lock()
	delete(s.Manager.tasks, id)
	s.Manager.mu.Unlock()
	t.cancel()
	c.Status(204)
}

type controlKey struct{}

func HTTPHandler(r http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := context.WithValue(req.Context(), controlKey{}, http.NewResponseController(w))
		r.ServeHTTP(w, req.WithContext(ctx))
	})
}
func writeEvent(c *gin.Context, event probe.ProgressEvent) error {
	if rc, ok := c.Request.Context().Value(controlKey{}).(*http.ResponseController); ok {
		rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	}
	data, e := json.Marshal(event)
	if e != nil {
		return e
	}
	_, e = fmt.Fprintf(c.Writer, "id: %d\nevent: message\ndata: %s\n\n", event.ID, data)
	if e == nil {
		c.Writer.Flush()
	}
	return e
}
func (s *Server) stream(c *gin.Context) {
	t, ok := s.find(c, c.Param("task_id"))
	if !ok {
		return
	}
	cursor := 0
	raw := c.GetHeader("Last-Event-ID")
	if raw == "" {
		raw = c.Query("after")
	}
	if raw != "" {
		var e error
		cursor, e = strconv.Atoi(raw)
		if e != nil || cursor < 0 {
			c.JSON(400, gin.H{"error": "invalid event cursor"})
			return
		}
	}
	t.mu.RLock()
	length := len(t.events)
	t.mu.RUnlock()
	if cursor > length {
		c.JSON(400, gin.H{"error": "event cursor exceeds task history"})
		return
	}
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-store")
	c.Header("X-Accel-Buffering", "no")
	ticker := time.NewTicker(12 * time.Second)
	defer ticker.Stop()
	for {
		t.mu.RLock()
		events := append([]probe.ProgressEvent(nil), t.events[cursor:]...)
		notify := t.notify
		finished := terminal(t.state.Status)
		t.mu.RUnlock()
		for _, ev := range events {
			if e := writeEvent(c, ev); e != nil {
				return
			}
			cursor = ev.ID
			if ev.Finished {
				return
			}
		}
		if finished {
			return
		}
		select {
		case <-c.Request.Context().Done():
			return
		case <-notify:
		case <-ticker.C:
			if rc, ok := c.Request.Context().Value(controlKey{}).(*http.ResponseController); ok {
				rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			}
			if _, e := fmt.Fprint(c.Writer, ": heartbeat\n\n"); e != nil {
				return
			}
			c.Writer.Flush()
		}
	}
}
func (s *Server) exportClash(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, s.cfg.MaxBodyBytes)
	var req struct {
		TaskID   string   `json:"task_id"`
		NodeIDs  []string `json:"node_ids"`
		MinScore int      `json:"min_score"`
		OnlyRes  bool     `json:"only_res"`
	}
	if c.ShouldBindJSON(&req) != nil || req.MinScore < 0 || req.MinScore > 100 {
		c.JSON(400, gin.H{"error": "invalid export payload"})
		return
	}
	t, ok := s.find(c, req.TaskID)
	if !ok {
		return
	}
	state := t.snapshot(true)
	ids := map[string]bool{}
	for _, id := range req.NodeIDs {
		ids[id] = true
	}
	var proxies []map[string]interface{}
	var names []string
	for _, res := range state.Results {
		if !res.Success || len(ids) > 0 && !ids[res.NodeID] {
			continue
		}
		if req.MinScore > 0 && (res.Purity == nil || !res.Purity.Verified || res.Purity.PurityScore == nil || *res.Purity.PurityScore < req.MinScore) {
			continue
		}
		if req.OnlyRes && (res.Purity == nil || !res.Purity.TypeVerified || res.Purity.IPType != "residential") {
			continue
		}
		if p := t.raw[res.NodeID]; p != nil {
			proxies = append(proxies, p)
			names = append(names, textName(p["name"]))
		}
	}
	if len(proxies) == 0 {
		c.JSON(400, gin.H{"error": "no nodes match; unknown or heuristic risk/type cannot satisfy verified score/residential filters"})
		return
	}
	cfg := map[string]interface{}{"mixed-port": 7890, "allow-lan": false, "mode": "rule", "log-level": "warning", "proxies": proxies, "proxy-groups": []map[string]interface{}{{"name": "PROXIES", "type": "select", "proxies": names}}, "rules": []string{"MATCH,PROXIES"}}
	data, e := yaml.Marshal(cfg)
	if e != nil {
		c.JSON(500, gin.H{"error": "cannot encode export"})
		return
	}
	c.Header("Content-Disposition", "attachment; filename=nodepure_filtered.yaml")
	c.Data(200, "application/yaml", data)
}
func textName(v interface{}) string { s, _ := v.(string); return s }
func csvSafe(s string) string {
	trim := strings.TrimLeft(s, " \t\r\n\ufeff")
	if trim != "" && strings.ContainsRune("=+-@", rune(trim[0])) || strings.HasPrefix(s, "\t") || strings.HasPrefix(s, "\r") || strings.HasPrefix(s, "\n") {
		return "'" + s
	}
	return s
}
func (s *Server) exportCSV(c *gin.Context) {
	t, ok := s.find(c, c.Param("task_id"))
	if !ok {
		return
	}
	state := t.snapshot(true)
	buf := &bytes.Buffer{}
	w := csv.NewWriter(buf)
	w.Write([]string{"节点名称", "协议", "连接", "出口IP", "国家", "城市", "ISP", "ASN", "网络类型", "原生性", "纯净度_越高越好", "风险状态", "GPT网页", "Claude网页", "HTTP延迟ms", "元数据来源", "采样时间", "风险分_越低越好", "评分来源", "评分查询时间", "评分状态", "评分依据"})
	for _, res := range state.Results {
		row := make([]string, 22)
		row[0], row[1] = res.NodeName, res.NodeType
		row[2] = "失败"
		if res.Success {
			row[2] = "成功"
		}
		if p := res.IPInfo; p != nil {
			row[3], row[4], row[5], row[6], row[7], row[15], row[16] = p.IP, p.Country, p.City, p.ISP, p.ASN, p.Source, p.SourceAt
		}
		if p := res.Purity; p != nil {
			row[8], row[9], row[11] = p.IPTypeLabel, p.NativeLabel, p.RiskLabel
			if p.Verified && p.PurityScore != nil {
				row[10] = strconv.Itoa(*p.PurityScore)
			}
			if p.Verified && p.FraudScore != nil {
				row[17] = strconv.Itoa(*p.FraudScore)
			}
			row[18], row[19], row[20], row[21] = p.Source, p.SourceAt, p.Status, p.Reason
		}
		if p := res.Services; p != nil {
			row[12], row[13] = p.ChatGPT, p.Claude
		}
		if p := res.Latency; p != nil && p.HTTPRTT >= 0 {
			row[14] = strconv.Itoa(p.HTTPRTT)
		}
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		w.Write(row)
	}
	w.Flush()
	if w.Error() != nil {
		c.JSON(500, gin.H{"error": "CSV encoding failed"})
		return
	}
	c.Header("Content-Disposition", "attachment; filename=nodepure_report.csv")
	c.Data(200, "text/csv; charset=utf-8", buf.Bytes())
}
