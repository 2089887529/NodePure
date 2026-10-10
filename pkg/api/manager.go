package api

import (
	"context"
	"fmt"
	"github.com/2089887529/NodePure/pkg/config"
	"github.com/2089887529/NodePure/pkg/core"
	"github.com/2089887529/NodePure/pkg/probe"
	"sort"
	"sync"
	"time"
)

type TaskSnapshot struct {
	ID         string               `json:"id"`
	Status     string               `json:"status"`
	Total      int                  `json:"total"`
	Completed  int                  `json:"completed"`
	CreatedAt  time.Time            `json:"created_at"`
	FinishedAt time.Time            `json:"finished_at,omitempty"`
	Error      string               `json:"error,omitempty"`
	Results    []*probe.ProbeResult `json:"results,omitempty"`
}
type Task struct {
	mu          sync.RWMutex
	Owner       string
	state       TaskSnapshot
	events      []probe.ProgressEvent
	notify      chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	nodes       []*core.ProxyNode
	warnings    []core.ParseWarning
	concurrency int
	raw         map[string]map[string]interface{}
}

func (t *Task) snapshot(include bool) TaskSnapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s := t.state
	if include {
		s.Results = append([]*probe.ProbeResult(nil), t.state.Results...)
	} else {
		s.Results = nil
	}
	return s
}
func terminal(s string) bool { return s == "completed" || s == "failed" || s == "canceled" }
func (t *Task) publish(res *probe.ProbeResult, status, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if terminal(t.state.Status) {
		return
	}
	if res != nil {
		t.state.Results = append(t.state.Results, res)
		t.state.Completed = len(t.state.Results)
	}
	if status != "" {
		t.state.Status = status
	}
	if reason != "" {
		t.state.Error = reason
	}
	if terminal(t.state.Status) {
		t.state.FinishedAt = time.Now().UTC()
	}
	t.events = append(t.events, probe.ProgressEvent{ID: len(t.events) + 1, TaskID: t.state.ID, Total: t.state.Total, Completed: t.state.Completed, Current: res, Finished: terminal(t.state.Status), Status: t.state.Status, Error: t.state.Error})
	close(t.notify)
	t.notify = make(chan struct{})
}

type Runner func(context.Context, []*core.ProxyNode, int, func(*probe.ProbeResult)) error
type Manager struct {
	cfg    *config.Config
	mu     sync.RWMutex
	tasks  map[string]*Task
	queue  chan *Task
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	run    Runner
}

func NewManager(cfg *config.Config, runner Runner) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{cfg: cfg, tasks: map[string]*Task{}, queue: make(chan *Task, cfg.MaxActiveTasks+cfg.QueueSize), ctx: ctx, cancel: cancel}
	if runner == nil {
		engine := probe.NewEngine(cfg.MaxConcurrency)
		runner = func(ctx context.Context, nodes []*core.ProxyNode, n int, emit func(*probe.ProbeResult)) error {
			k, e := core.StartKernelForNodes(ctx, nodes)
			if e != nil {
				return e
			}
			defer k.Stop()
			for _, bad := range k.Rejected {
				for _, node := range nodes {
					if node.ID == bad.NodeID {
						emit(probe.Failure(node, bad.Reason))
						break
					}
				}
			}
			probeCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			go func() {
				select {
				case <-k.Done:
					cancel()
				case <-probeCtx.Done():
				}
			}()
			engine.Run(probeCtx, k.Nodes, n, emit)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			select {
			case <-k.Done:
				return fmt.Errorf("probe kernel exited")
			default:
				return nil
			}
		}
	}
	m.run = runner
	for i := 0; i < cfg.MaxActiveTasks; i++ {
		m.wg.Add(1)
		go m.worker()
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.mu.Lock()
				m.pruneLocked()
				m.mu.Unlock()
			}
		}
	}()
	return m
}
func (m *Manager) pruneLocked() {
	for id, t := range m.tasks {
		s := t.snapshot(false)
		if terminal(s.Status) && time.Since(s.FinishedAt) > m.cfg.TaskTTL {
			delete(m.tasks, id)
			t.cancel()
		}
	}
}
func (m *Manager) Add(owner string, nodes []*core.ProxyNode, warnings []core.ParseWarning, concurrency int) (*Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return nil, fmt.Errorf("server shutting down")
	}
	m.pruneLocked()
	active := 0
	for _, t := range m.tasks {
		if !terminal(t.snapshot(false).Status) {
			active++
		}
	}
	if len(m.tasks) >= m.cfg.MaxTasks || active >= m.cfg.MaxActiveTasks+m.cfg.QueueSize {
		return nil, fmt.Errorf("task capacity reached; wait or delete completed tasks")
	}
	id, e := randomID()
	if e != nil {
		return nil, fmt.Errorf("cannot create task")
	}
	if concurrency <= 0 {
		concurrency = m.cfg.MaxConcurrency
	}
	if concurrency > m.cfg.MaxConcurrency {
		concurrency = m.cfg.MaxConcurrency
	}
	ctx, cancel := context.WithTimeout(m.ctx, m.cfg.TaskTimeout)
	t := &Task{Owner: owner, state: TaskSnapshot{ID: "task-" + id, Status: "queued", Total: len(nodes) + len(warnings), CreatedAt: time.Now().UTC()}, notify: make(chan struct{}), ctx: ctx, cancel: cancel, nodes: nodes, warnings: warnings, concurrency: concurrency, raw: map[string]map[string]interface{}{}}
	for _, n := range nodes {
		t.raw[n.ID] = n.RawConfig
	}
	m.tasks[t.state.ID] = t
	select {
	case m.queue <- t:
		return t, nil
	default:
		delete(m.tasks, t.state.ID)
		cancel()
		return nil, fmt.Errorf("task queue full")
	}
}
func (m *Manager) worker() {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			return
		case t := <-m.queue:
			if t.ctx.Err() != nil {
				t.publish(nil, "canceled", "任务已取消或超时")
				continue
			}
			t.publish(nil, "running", "")
			for _, w := range t.warnings {
				t.publish(&probe.ProbeResult{NodeID: w.NodeID, NodeName: w.Name, NodeType: "invalid", Error: w.Reason, CompletedAt: time.Now().UTC().Format(time.RFC3339)}, "", "")
			}
			e := m.run(t.ctx, t.nodes, t.concurrency, func(res *probe.ProbeResult) { t.publish(res, "", "") })
			if t.ctx.Err() != nil {
				t.publish(nil, "canceled", "任务已取消或达到截止时间")
			} else if e != nil {
				t.publish(nil, "failed", e.Error())
			} else if t.snapshot(false).Completed != t.snapshot(false).Total {
				t.publish(nil, "failed", "探测结果不完整")
			} else {
				t.publish(nil, "completed", "")
			}
			t.cancel()
		}
	}
}
func (m *Manager) lookup(id, owner string) (*Task, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tasks[id]
	return t, ok && t.Owner == owner
}
func (m *Manager) list(owner string) []TaskSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []TaskSnapshot{}
	for _, t := range m.tasks {
		if t.Owner == owner {
			out = append(out, t.snapshot(false))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}
func (m *Manager) Close() {
	m.cancel()
	m.mu.RLock()
	for _, t := range m.tasks {
		t.cancel()
		t.publish(nil, "canceled", "服务器正在关闭")
	}
	m.mu.RUnlock()
	m.wg.Wait()
}
