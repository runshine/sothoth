package orchestrator

import (
	"context"
	"encoding/json"
	"testing"
)

func fresh(t *testing.T) (*Store, context.Context) {
	t.Helper()
	s, e := Open(":memory:")
	if e != nil {
		t.Fatal(e)
	}
	return s, context.Background()
}
func makeTask(t *testing.T, s *Store, c CreateTask) Task {
	x, e := s.Create(context.Background(), "p", c)
	if e != nil {
		t.Fatal(e)
	}
	return x
}
func TestAllFlowsHaveExpectedRoot(t *testing.T) {
	cases := []struct{ typ, p, stage string }{{"binary", "", "firmware_unpack"}, {"binary_module", "", "binary_to_source"}, {"source", "", "system_analysis"}, {"source", "kg_source_vuln_scan", "knowledge_graph_entry_fetch"}}
	for _, c := range cases {
		t.Run(c.typ+c.p, func(t *testing.T) {
			s, ctx := fresh(t)
			task := makeTask(t, s, CreateTask{TaskType: c.typ, PipelineProfile: c.p, Input: json.RawMessage(`{"items":[{"module_key":"m"}]}`)})
			j, e := s.Start(ctx, task.ID)
			if e != nil || len(j) != 1 {
				t.Fatalf("start: %v jobs=%d", e, len(j))
			}
			items, err := s.Items(ctx, task.ID)
			if err != nil {
				t.Fatal(err)
			}
			if items[0].Stage != c.stage {
				t.Fatalf("got %s", items[0].Stage)
			}
		})
	}
}
func TestStreamingDeduplicatesAndAdvances(t *testing.T) {
	s, ctx := fresh(t)
	task := makeTask(t, s, CreateTask{TaskType: "source", Input: json.RawMessage(`{"items":[{"firmware_key":"f"}]}`)})
	root, _ := s.Start(ctx, task.ID)
	entry, _ := s.Complete(ctx, task.ID, root[0].ItemID, Completion{Status: Success, Result: json.RawMessage(`{"modules":[{"module_key":"m"}]}`)})
	jobs, e := s.Complete(ctx, task.ID, entry[0].ItemID, Completion{Status: Success, Result: json.RawMessage(`{"entries":[{"function_id":"f"},{"function_id":"f"}]}`)})
	if e != nil || len(jobs) != 1 {
		t.Fatalf("jobs=%d err=%v", len(jobs), e)
	}
	got, _ := s.Task(ctx, task.ID)
	if got.CurrentStage != "dataflow_vuln_scan" || got.Status != Running {
		t.Fatalf("not streaming: %#v", got)
	}
}
func TestTerminalAndCancel(t *testing.T) {
	s, ctx := fresh(t)
	task := makeTask(t, s, CreateTask{TaskType: "binary_module", Input: json.RawMessage(`{}`)})
	j, _ := s.Start(ctx, task.ID)
	s.Complete(ctx, task.ID, j[0].ItemID, Completion{Status: Failed, Error: "bad"})
	x, _ := s.Task(ctx, task.ID)
	if x.Status != Failed {
		t.Fatal(x.Status)
	}
	task = makeTask(t, s, CreateTask{TaskType: "source", Input: json.RawMessage(`{}`)})
	s.Start(ctx, task.ID)
	if e := s.Cancel(ctx, task.ID); e != nil {
		t.Fatal(e)
	}
	x, _ = s.Task(ctx, task.ID)
	if x.Status != Cancelled {
		t.Fatal(x.Status)
	}
}
