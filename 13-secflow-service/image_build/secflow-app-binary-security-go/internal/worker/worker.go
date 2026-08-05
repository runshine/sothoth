package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/GaiaSecHW/secflow-app-binary-security-go/internal/orchestrator"
)

type Worker struct {
	Store        *orchestrator.Store
	Client       *http.Client
	MaxAttempts  int
	ClaimTimeout time.Duration
}

func New(s *orchestrator.Store) *Worker {
	return &Worker{Store: s, Client: &http.Client{Timeout: 30 * time.Second}, MaxAttempts: 3, ClaimTimeout: 2 * time.Minute}
}

func (w *Worker) Run(ctx context.Context) error {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			if err := w.Step(ctx); err != nil {
				return err
			}
		}
	}
}
func (w *Worker) Cancel(ctx context.Context, taskID string) error {
	task, e := w.Store.Task(ctx, taskID)
	if e != nil {
		return e
	}
	items, e := w.Store.ActiveItems(ctx, taskID)
	if e != nil {
		return e
	}
	for _, i := range items {
		base := os.Getenv("DOWNSTREAM_" + upper(i.Stage) + "_BASE_URL")
		if base == "" {
			continue
		}
		resp, e := w.request(ctx, http.MethodPost, join(base, cancelPath(i.Stage, task.ProjectID, i.DownstreamTaskID.String)), nil)
		if e != nil {
			return e
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			e = responseError(resp)
		}
		resp.Body.Close()
		if e != nil {
			return e
		}
	}
	return w.Store.Cancel(ctx, taskID)
}
func (w *Worker) Step(ctx context.Context) error {
	if _, e := w.Store.RecoverUnboundRunning(ctx, time.Now().Add(-w.ClaimTimeout), 16); e != nil {
		return e
	}
	items, e := w.Store.ClaimPending(ctx, 16)
	if e != nil {
		return e
	}
	for _, item := range items {
		if e = w.dispatch(ctx, item); e != nil {
			_ = w.Store.DispatchFailed(ctx, item.ID, e.Error())
		}
	}
	running, e := w.Store.RunningItems(ctx, 32)
	if e != nil {
		return e
	}
	for _, item := range running {
		status, result, e := w.poll(ctx, item)
		if e != nil {
			continue
		}
		if status == orchestrator.Success || status == orchestrator.Failed || status == orchestrator.Cancelled {
			_, e = w.Store.Complete(ctx, item.TaskID, item.ID, orchestrator.Completion{Status: status, Result: result, Error: statusError(status, result)})
		}
		if e != nil {
			return e
		}
	}
	return nil
}

func (w *Worker) dispatch(ctx context.Context, item orchestrator.Item) error {
	if item.Stage == "knowledge_graph_entry_fetch" {
		return w.fetchKnowledgeGraphEntries(ctx, item)
	}
	task, e := w.Store.Task(ctx, item.TaskID)
	if e != nil {
		return e
	}
	base := os.Getenv("DOWNSTREAM_" + upper(item.Stage) + "_BASE_URL")
	if base == "" {
		return fmt.Errorf("DOWNSTREAM_%s_BASE_URL is not configured", upper(item.Stage))
	}
	path := createPath(item.Stage, task.ProjectID)
	payload, e := createPayload(item.Stage, task.ProjectID, item)
	if e != nil {
		return e
	}
	body, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	resp, e := w.request(ctx, http.MethodPost, join(base, path), body)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return responseError(resp)
	}
	var created map[string]any
	if e = json.NewDecoder(resp.Body).Decode(&created); e != nil {
		return e
	}
	id := stringValue(created, "task_id", "id")
	if id == "" {
		return fmt.Errorf("%s create response has no task_id", item.Stage)
	}
	return w.Store.SetDownstreamTask(ctx, item.ID, id)
}
func (w *Worker) fetchKnowledgeGraphEntries(ctx context.Context, item orchestrator.Item) error {
	var p map[string]any
	if e := json.Unmarshal(item.Payload, &p); e != nil {
		return e
	}
	base := os.Getenv("KNOWLEDGE_GRAPH_AUDIT_BASE_URL")
	if base == "" {
		return fmt.Errorf("KNOWLEDGE_GRAPH_AUDIT_BASE_URL is not configured")
	}
	uploadID := fmt.Sprint(p["upload_id"])
	dbName := fmt.Sprint(p["db_name"])
	var path string
	if uploadID != "" && uploadID != "<nil>" {
		path = "/uploads/" + url.PathEscape(uploadID) + "/audit/sources"
	} else if dbName != "" && dbName != "<nil>" {
		path = "/projects/" + url.PathEscape(dbName) + "/audit/sources"
	} else {
		return fmt.Errorf("knowledge graph input requires upload_id or db_name")
	}
	u := join(base, path)
	q := url.Values{"status": {firstString(p, "status_filter", "identified")}, "include_excluded": {firstString(p, "include_excluded", "false")}}
	resp, e := w.request(ctx, http.MethodGet, u+"?"+q.Encode(), nil)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return responseError(resp)
	}
	var data struct {
		Items []map[string]any `json:"items"`
	}
	if e = json.NewDecoder(resp.Body).Decode(&data); e != nil {
		return e
	}
	entries := make([]map[string]any, 0)
	for _, candidate := range data.Items {
		if enabled, ok := candidate["is_entry"].(bool); ok && enabled {
			entries = append(entries, candidate)
		}
	}
	result, _ := json.Marshal(map[string]any{"entries": entries})
	_, e = w.Store.Complete(ctx, item.TaskID, item.ID, orchestrator.Completion{Status: orchestrator.Success, Result: result})
	return e
}

func (w *Worker) poll(ctx context.Context, item orchestrator.Item) (orchestrator.Status, json.RawMessage, error) {
	task, e := w.Store.Task(ctx, item.TaskID)
	if e != nil {
		return "", nil, e
	}
	base := os.Getenv("DOWNSTREAM_" + upper(item.Stage) + "_BASE_URL")
	if base == "" {
		return "", nil, fmt.Errorf("missing downstream base")
	}
	path := statusPath(item.Stage, task.ProjectID, item.DownstreamTaskID.String)
	resp, e := w.request(ctx, http.MethodGet, join(base, path), nil)
	if e != nil {
		return "", nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", nil, responseError(resp)
	}
	var data map[string]any
	if e = json.NewDecoder(resp.Body).Decode(&data); e != nil {
		return "", nil, e
	}
	status := mapStatus(stringValue(data, "status", "state"))
	result, _ := json.Marshal(resultValue(data))
	return status, result, nil
}

func createPath(stage, project string) string {
	switch stage {
	case "firmware_unpack":
		return "/api/app/firmware-unpacker/projects/" + project + "/tasks"
	case "binary_to_source":
		return "/api/app/binary-to-source/projects/" + project + "/tasks"
	case "system_analysis":
		return "/api/app/system-analyse/tasks"
	case "entry_analysis":
		return "/api/app/entry-analyse/tasks"
	case "dataflow_vuln_scan":
		return "/api/app/dataflow-vuln-scan/tasks"
	}
	return ""
}
func statusPath(stage, project, id string) string {
	switch stage {
	case "firmware_unpack":
		return "/api/app/firmware-unpacker/projects/" + project + "/tasks/" + id
	case "binary_to_source":
		return "/api/app/binary-to-source/projects/" + project + "/tasks/" + id
	case "system_analysis":
		return "/api/app/system-analyse/tasks/" + id
	case "entry_analysis":
		return "/api/app/entry-analyse/tasks/" + id
	case "dataflow_vuln_scan":
		return "/api/app/dataflow-vuln-scan/tasks/" + id
	}
	return ""
}
func cancelPath(stage, project, id string) string {
	switch stage {
	case "binary_to_source":
		return "/api/app/binary-to-source/projects/" + project + "/tasks/" + id + "/terminate"
	case "firmware_unpack":
		return "/api/app/firmware-unpacker/tasks/" + id + "/cancel"
	case "system_analysis":
		return "/api/app/system-analyse/tasks/" + id + "/cancel"
	case "entry_analysis":
		return "/api/app/entry-analyse/tasks/" + id + "/cancel"
	case "dataflow_vuln_scan":
		return "/api/app/dataflow-vuln-scan/tasks/" + id + "/cancel"
	}
	return ""
}
func createPayload(stage, project string, item orchestrator.Item) (map[string]any, error) {
	var p map[string]any
	if e := json.Unmarshal(item.Payload, &p); e != nil {
		return nil, e
	}
	p["project_id"] = project
	p["idempotency_key"] = item.ID
	p["parent_task_id"] = item.TaskID
	p["parent_stage_item_id"] = item.ID
	switch stage {
	case "firmware_unpack":
		p["firmware_path"] = first(p, "firmware_path", "path", "input_path")
	case "system_analysis":
		p["task_name"] = firstDefault(p, "task_name", item.ItemKey+"-system-analysis")
		p["input_path"] = first(p, "input_path", "path", "source_path")
		p["analysis_mode"] = firstDefault(p, "analysis_mode", "binary")
	case "binary_to_source":
		p["name"] = firstDefault(p, "name", item.ItemKey)
		if _, ok := p["elf_tasks"]; !ok {
			p["elf_tasks"] = []any{copyMap(p)}
		}
	case "entry_analysis", "knowledge_graph_entry_fetch":
		p["task_name"] = firstDefault(p, "task_name", item.ItemKey+"-entry")
		p["input_path"] = first(p, "input_path", "module_dir", "path")
		p["module_name"] = first(p, "module_name", "module_key", "name")
		p["source_path"] = first(p, "source_path", "source_root", "source_root_path")
	case "dataflow_vuln_scan":
		p["task_name"] = firstDefault(p, "task_name", item.ItemKey+"-scan")
		p["input_path"] = first(p, "input_path", "module_input_path", "module_dir")
		p["module_input_path"] = first(p, "module_input_path", "input_path", "module_dir")
		p["source_root_path"] = first(p, "source_root_path", "source_root", "source_dir")
		p["prompt_content"] = firstDefault(p, "prompt_content", "分析该入口函数的外部输入数据流")
	}
	return p, nil
}
func (w *Worker) request(ctx context.Context, method, url string, body []byte) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, e := http.NewRequestWithContext(ctx, method, url, r)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	if token := os.Getenv("DOWNSTREAM_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return w.Client.Do(req)
}
func responseError(r *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	return fmt.Errorf("downstream returned %s: %s", r.Status, strings.TrimSpace(string(b)))
}
func resultValue(v map[string]any) any {
	if x, ok := v["result"]; ok {
		return x
	}
	return v
}
func mapStatus(s string) orchestrator.Status {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "success", "succeeded", "completed", "done", "finished":
		return orchestrator.Success
	case "failed", "error":
		return orchestrator.Failed
	case "cancelled", "canceled":
		return orchestrator.Cancelled
	default:
		return orchestrator.Running
	}
}
func statusError(s orchestrator.Status, r json.RawMessage) string {
	if s != orchestrator.Failed {
		return ""
	}
	return string(r)
}
func first(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil && fmt.Sprint(v) != "" {
			return v
		}
	}
	return ""
}
func firstDefault(m map[string]any, k, d string) any {
	if v := first(m, k); fmt.Sprint(v) != "" {
		return v
	}
	return d
}
func firstString(m map[string]any, k, d string) string {
	v := first(m, k)
	if fmt.Sprint(v) == "" {
		return d
	}
	return fmt.Sprint(v)
}
func copyMap(source map[string]any) map[string]any {
	out := make(map[string]any, len(source))
	for k, v := range source {
		out[k] = v
	}
	return out
}
func stringValue(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return fmt.Sprint(v)
		}
	}
	return ""
}
func join(base, path string) string { return strings.TrimRight(base, "/") + path }
func upper(s string) string         { return strings.ToUpper(strings.ReplaceAll(s, "-", "_")) }
