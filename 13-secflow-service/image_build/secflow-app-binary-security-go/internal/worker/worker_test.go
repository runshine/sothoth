package worker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/GaiaSecHW/secflow-app-binary-security-go/internal/orchestrator"
)

func TestStepCreatesAndPollsRealSystemContract(t *testing.T) {
	var posts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			atomic.AddInt32(&posts, 1)
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["project_id"] != "project-1" || body["input_path"] != "/input/fw" {
				t.Fatalf("unexpected payload: %#v", body)
			}
			json.NewEncoder(w).Encode(map[string]any{"task_id": "downstream-1"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "result": map[string]any{"modules": []any{map[string]any{"module_key": "m"}}}})
	}))
	defer server.Close()
	t.Setenv("DOWNSTREAM_SYSTEM_ANALYSIS_BASE_URL", server.URL)
	s, _ := orchestrator.Open(":memory:")
	task, _ := s.Create(context.Background(), "project-1", orchestrator.CreateTask{TaskType: "source", Input: json.RawMessage(`{"items":[{"input_path":"/input/fw","firmware_key":"fw"}]}`)})
	jobs, e := s.Start(context.Background(), task.ID)
	if e != nil || len(jobs) != 1 {
		t.Fatal(e)
	}
	if e = New(s).Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	got, e := s.Task(context.Background(), task.ID)
	if e != nil {
		t.Fatal(e)
	}
	if got.CurrentStage != "entry_analysis" {
		t.Fatalf("stage=%s", got.CurrentStage)
	}
	if posts != 1 {
		t.Fatalf("posts=%d", posts)
	}
}

func TestDispatchFailureIsRetriedBeforeTerminal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	t.Setenv("DOWNSTREAM_SYSTEM_ANALYSIS_BASE_URL", server.URL)
	s, _ := orchestrator.Open(":memory:")
	task, _ := s.Create(context.Background(), "p", orchestrator.CreateTask{TaskType: "source", Input: json.RawMessage(`{"items":[{"input_path":"/input/fw"}]}`)})
	s.Start(context.Background(), task.ID)
	w := New(s)
	for n := 0; n < 2; n++ {
		if e := w.Step(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	items, _ := s.Items(context.Background(), task.ID)
	if items[0].Status != orchestrator.Pending {
		t.Fatalf("status after retry=%s", items[0].Status)
	}
	if e := w.Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	items, _ = s.Items(context.Background(), task.ID)
	if items[0].Status != orchestrator.Failed {
		t.Fatalf("status after terminal retry=%s", items[0].Status)
	}
	finalTask, _ := s.Task(context.Background(), task.ID)
	if finalTask.Status != orchestrator.Failed {
		t.Fatalf("task status after terminal retry=%s", finalTask.Status)
	}
}

func TestKnowledgeGraphStageFetchesEntriesWithoutChildTask(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/uploads/upload-1/audit/sources" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"is_entry": true, "function_id": "f"}, map[string]any{"is_entry": false, "function_id": "skip"}}})
	}))
	defer server.Close()
	t.Setenv("KNOWLEDGE_GRAPH_AUDIT_BASE_URL", server.URL)
	s, _ := orchestrator.Open(":memory:")
	task, _ := s.Create(context.Background(), "p", orchestrator.CreateTask{TaskType: "source", PipelineProfile: "kg_source_vuln_scan", Input: json.RawMessage(`{"items":[{"upload_id":"upload-1"}]}`)})
	s.Start(context.Background(), task.ID)
	if e := New(s).Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	items, _ := s.Items(context.Background(), task.ID)
	if len(items) != 2 || items[1].Stage != "dataflow_vuln_scan" || items[1].ItemKey != "f" {
		t.Fatalf("unexpected items %#v", items)
	}
}

func TestBinaryFlowReachesTerminalThroughDownstreamPolling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stage := ""
		switch {
		case strings.Contains(r.URL.Path, "firmware-unpacker"):
			stage = "firmware_unpack"
		case strings.Contains(r.URL.Path, "system-analyse"):
			stage = "system_analysis"
		case strings.Contains(r.URL.Path, "binary-to-source"):
			stage = "binary_to_source"
		case strings.Contains(r.URL.Path, "entry-analyse"):
			stage = "entry_analysis"
		case strings.Contains(r.URL.Path, "dataflow-vuln-scan"):
			stage = "dataflow_vuln_scan"
		}
		if r.Method == http.MethodPost {
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			switch stage {
			case "firmware_unpack":
				if body["firmware_path"] != "/firmware.bin" {
					t.Fatalf("firmware contract: %#v", body)
				}
			case "system_analysis":
				if body["input_path"] != "/unpacked" {
					t.Fatalf("system contract: %#v", body)
				}
			case "binary_to_source":
				if _, ok := body["elf_tasks"]; !ok {
					t.Fatalf("b2s contract: %#v", body)
				}
			case "entry_analysis":
				if body["module_name"] != "m" || body["source_path"] != "/src" {
					t.Fatalf("entry contract: %#v", body)
				}
			case "dataflow_vuln_scan":
				if body["module_input_path"] != "/mod" || body["source_root_path"] != "/src" {
					t.Fatalf("dataflow contract: %#v", body)
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"task_id": stage})
			return
		}
		result := map[string]any{}
		switch stage {
		case "firmware_unpack":
			result["firmwares"] = []any{map[string]any{"firmware_key": "fw", "input_path": "/unpacked"}}
		case "system_analysis":
			result["modules"] = []any{map[string]any{"module_key": "m", "module_name": "m", "module_dir": "/mod", "source_root": "/src"}}
		case "binary_to_source":
			result["modules"] = []any{map[string]any{"module_key": "m", "module_name": "m", "module_dir": "/mod", "source_root": "/src"}}
		case "entry_analysis":
			result["entries"] = []any{map[string]any{"function_id": "f", "function_name": "f", "module_input_path": "/mod", "source_root_path": "/src"}}
		case "dataflow_vuln_scan":
			result["results"] = []any{map[string]any{"ok": true}}
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "result": result})
	}))
	defer server.Close()
	for _, name := range []string{"FIRMWARE_UNPACK", "SYSTEM_ANALYSIS", "BINARY_TO_SOURCE", "ENTRY_ANALYSIS", "DATAFLOW_VULN_SCAN"} {
		t.Setenv("DOWNSTREAM_"+name+"_BASE_URL", server.URL)
	}
	s, _ := orchestrator.Open(":memory:")
	task, _ := s.Create(context.Background(), "p", orchestrator.CreateTask{TaskType: "binary", Input: json.RawMessage(`{"items":[{"firmware_path":"/firmware.bin","firmware_key":"fw"}]}`)})
	s.Start(context.Background(), task.ID)
	w := New(s)
	for n := 0; n < 5; n++ {
		if e := w.Step(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	got, _ := s.Task(context.Background(), task.ID)
	if got.Status != orchestrator.Success || got.CurrentStage != "dataflow_vuln_scan" {
		items, _ := s.Items(context.Background(), task.ID)
		t.Fatalf("task=%#v items=%#v", got, items)
	}
}

func TestSourceAndBinaryModuleFlowsReachTerminal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stage := ""
		switch {
		case strings.Contains(r.URL.Path, "system-analyse"):
			stage = "system_analysis"
		case strings.Contains(r.URL.Path, "binary-to-source"):
			stage = "binary_to_source"
		case strings.Contains(r.URL.Path, "entry-analyse"):
			stage = "entry_analysis"
		case strings.Contains(r.URL.Path, "dataflow-vuln-scan"):
			stage = "dataflow_vuln_scan"
		}
		if r.Method == http.MethodPost {
			json.NewEncoder(w).Encode(map[string]any{"task_id": stage})
			return
		}
		result := map[string]any{}
		switch stage {
		case "system_analysis", "binary_to_source":
			result["modules"] = []any{map[string]any{"module_key": "m", "module_name": "m", "module_dir": "/mod", "source_root": "/src"}}
		case "entry_analysis":
			result["entries"] = []any{map[string]any{"function_id": "f", "module_input_path": "/mod", "source_root_path": "/src"}}
		case "dataflow_vuln_scan":
			result["results"] = []any{map[string]any{"ok": true}}
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "result": result})
	}))
	defer server.Close()
	for _, name := range []string{"SYSTEM_ANALYSIS", "BINARY_TO_SOURCE", "ENTRY_ANALYSIS", "DATAFLOW_VULN_SCAN"} {
		t.Setenv("DOWNSTREAM_"+name+"_BASE_URL", server.URL)
	}
	for _, tc := range []struct {
		kind  string
		input string
		steps int
	}{{"source", `{"items":[{"input_path":"/source"}]}`, 3}, {"binary_module", `{"items":[{"module_key":"m","module_name":"m","module_dir":"/mod","source_root":"/src"}]}`, 3}} {
		t.Run(tc.kind, func(t *testing.T) {
			s, _ := orchestrator.Open(":memory:")
			task, _ := s.Create(context.Background(), "p", orchestrator.CreateTask{TaskType: tc.kind, Input: json.RawMessage(tc.input)})
			s.Start(context.Background(), task.ID)
			w := New(s)
			for n := 0; n < tc.steps; n++ {
				if e := w.Step(context.Background()); e != nil {
					t.Fatal(e)
				}
			}
			got, _ := s.Task(context.Background(), task.ID)
			if got.Status != orchestrator.Success {
				t.Fatalf("task=%#v", got)
			}
		})
	}
}

func TestCancelPropagatesToActiveDownstream(t *testing.T) {
	var cancelled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/cancel") {
			cancelled.Store(true)
			json.NewEncoder(w).Encode(map[string]any{})
			return
		}
		if r.Method == http.MethodPost {
			json.NewEncoder(w).Encode(map[string]any{"task_id": "child"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "running"})
	}))
	defer server.Close()
	t.Setenv("DOWNSTREAM_SYSTEM_ANALYSIS_BASE_URL", server.URL)
	s, _ := orchestrator.Open(":memory:")
	task, _ := s.Create(context.Background(), "p", orchestrator.CreateTask{TaskType: "source", Input: json.RawMessage(`{"items":[{"input_path":"/input"}]}`)})
	s.Start(context.Background(), task.ID)
	w := New(s)
	if e := w.Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := w.Cancel(context.Background(), task.ID); e != nil {
		t.Fatal(e)
	}
	got, _ := s.Task(context.Background(), task.ID)
	if !cancelled.Load() || got.Status != orchestrator.Cancelled {
		t.Fatalf("cancelled=%t task=%s", cancelled.Load(), got.Status)
	}
}

func TestWorkerRecoversUnboundRunningItemAfterRestart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			json.NewEncoder(w).Encode(map[string]any{"task_id": "recovered-child"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "running"})
	}))
	defer server.Close()
	t.Setenv("DOWNSTREAM_SYSTEM_ANALYSIS_BASE_URL", server.URL)
	s, _ := orchestrator.Open(":memory:")
	task, _ := s.Create(context.Background(), "p", orchestrator.CreateTask{TaskType: "source", Input: json.RawMessage(`{"items":[{"input_path":"/input"}]}`)})
	s.Start(context.Background(), task.ID)
	claimed, e := s.ClaimPending(context.Background(), 1)
	if e != nil || len(claimed) != 1 {
		t.Fatal(e)
	}
	w := New(s)
	w.ClaimTimeout = 0
	if e = w.Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	items, _ := s.Items(context.Background(), task.ID)
	if !items[0].DownstreamTaskID.Valid || items[0].DownstreamTaskID.String != "recovered-child" {
		t.Fatalf("item was not recovered: %#v", items[0])
	}
}
