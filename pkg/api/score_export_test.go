package api

import (
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"testing"

	"github.com/2089887529/NodePure/pkg/core"
	"github.com/2089887529/NodePure/pkg/probe"
)

func TestScoreExportDirectionAndResidentialEvidence(t *testing.T) {
	s, r := testServer(t, func(_ context.Context, ns []*core.ProxyNode, _ int, emit func(*probe.ProbeResult)) error {
		for _, n := range ns {
			risk := 21
			if n.Name == "low" {
				risk = 20
			}
			pure := 100 - risk
			p := probe.AnalyzePurity(nil)
			p.FraudScore = &risk
			p.PurityScore = &pure
			p.Verified = true
			p.Status = "ok"
			p.Source = "test provider"
			p.SourceAt = "2026-10-10T00:00:00Z"
			p.Reason = "provider risk, purity=100-risk"
			p.IPType = "residential"
			p.TypeVerified = n.Name == "low"
			emit(&probe.ProbeResult{NodeID: n.ID, NodeName: n.Name, Success: true, Purity: p})
		}
		return nil
	})
	cookie := testSession(t, r)
	owner := s.Auth.sessionsKeyForTest(cookie.Value)
	task, err := s.Manager.Add(owner, []*core.ProxyNode{{ID: "low", Name: "low", RawConfig: map[string]interface{}{"name": "low"}}, {ID: "high", Name: "high", RawConfig: map[string]interface{}{"name": "high"}}}, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	awaitTask(t, task)
	w := apiRequest(r, "GET", "/api/export/csv/"+task.state.ID, "", cookie, false)
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil || len(rows) != 3 {
		t.Fatal("CSV", err)
	}
	for _, row := range rows[1:] {
		if row[18] != "test provider" || row[19] != "2026-10-10T00:00:00Z" || row[20] != "ok" {
			t.Fatal("missing provenance")
		}
		if row[0] == "low" && (row[10] != "80" || row[17] != "20") {
			t.Fatal("score directions reversed")
		}
	}
	for _, filter := range []string{`"min_score":80`, `"only_res":true`} {
		payload := fmt.Sprintf(`{"task_id":%q,%s}`, task.state.ID, filter)
		w := apiRequest(r, "POST", "/api/export/clash", payload, cookie, true)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "low") || strings.Contains(w.Body.String(), "high") {
			t.Fatal("filter exported high-risk or heuristic residential", w.Code)
		}
	}
}
