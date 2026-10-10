package probe

import (
	"context"
	"fmt"
	"github.com/2089887529/NodePure/pkg/config"
	"github.com/2089887529/NodePure/pkg/core"
	"sync"
	"time"
)

type ProbeResult struct {
	NodeID      string                 `json:"node_id"`
	NodeName    string                 `json:"node_name"`
	NodeType    string                 `json:"node_type"`
	Success     bool                   `json:"success"`
	Error       string                 `json:"error,omitempty"`
	IPInfo      *IPInfo                `json:"ip_info,omitempty"`
	Purity      *PurityAnalysis        `json:"purity,omitempty"`
	Services    *ServiceStatus         `json:"services,omitempty"`
	Latency     *LatencyMetrics        `json:"latency,omitempty"`
	CompletedAt string                 `json:"completed_at"`
	RawConfig   map[string]interface{} `json:"-"`
}
type ProgressEvent struct {
	ID        int          `json:"id"`
	TaskID    string       `json:"task_id"`
	Total     int          `json:"total"`
	Completed int          `json:"completed"`
	Current   *ProbeResult `json:"current,omitempty"`
	Finished  bool         `json:"finished"`
	Status    string       `json:"status,omitempty"`
	Error     string       `json:"error,omitempty"`
}
type Engine struct {
	slots      chan struct{}
	reputation *ReputationChecker
}

func NewEngine(max int) *Engine {
	if max < 1 {
		max = 1
	}
	return &Engine{slots: make(chan struct{}, max), reputation: NewReputationChecker(config.Global)}
}
func NewEngineWithConfig(cfg *config.Config) *Engine {
	max := cfg.MaxConcurrency
	if max < 1 {
		max = 1
	}
	return &Engine{slots: make(chan struct{}, max), reputation: NewReputationChecker(cfg)}
}
func (e *Engine) Run(ctx context.Context, nodes []*core.ProxyNode, concurrency int, emit func(*ProbeResult)) {
	if ctx.Err() != nil {
		return
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > cap(e.slots) {
		concurrency = cap(e.slots)
	}
	if concurrency > len(nodes) {
		concurrency = len(nodes)
	}
	work := make(chan *core.ProxyNode)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case n, ok := <-work:
					if !ok {
						return
					}
					select {
					case <-ctx.Done():
						return
					case e.slots <- struct{}{}:
					}
					if ctx.Err() != nil {
						<-e.slots
						return
					}
					res := probeSingleNode(ctx, n, e.reputation)
					<-e.slots
					emit(res)
				}
			}
		}()
	}
dispatch:
	for _, n := range nodes {
		select {
		case <-ctx.Done():
			break dispatch
		case work <- n:
		}
	}
	close(work)
	wg.Wait()
}
func Failure(node *core.ProxyNode, reason string) *ProbeResult {
	return &ProbeResult{NodeID: node.ID, NodeName: node.Name, NodeType: node.Type, Error: reason, CompletedAt: time.Now().UTC().Format(time.RFC3339)}
}
func probeSingleNode(parent context.Context, node *core.ProxyNode, reputation *ReputationChecker) *ProbeResult {
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	res := Failure(node, "")
	res.RawConfig = node.RawConfig
	client, err := NewProxyClient(node, 10*time.Second)
	if err != nil {
		res.Error = "cannot create proxy client"
		return res
	}
	defer client.CloseIdleConnections()
	info, err := FetchIPInfo(ctx, client)
	if err != nil {
		res.Error = fmt.Sprint(err)
		return res
	}
	res.Success = true
	res.IPInfo = info
	type webResults struct {
		services *ServiceStatus
		latency  *LatencyMetrics
	}
	web := make(chan webResults, 1)
	go func() { s, m := CheckServices(ctx, client); web <- webResults{s, m} }()
	res.Purity = reputation.Analyze(ctx, client, info)
	w := <-web
	res.Services, res.Latency = w.services, w.latency
	res.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	return res
}
