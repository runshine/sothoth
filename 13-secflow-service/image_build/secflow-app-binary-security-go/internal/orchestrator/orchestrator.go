package orchestrator

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
	"time"
)

type Flow string

const (
	Binary       Flow = "binary"
	BinaryModule Flow = "binary_module"
	Source       Flow = "source"
	KGSource     Flow = "kg_source_vuln_scan"
)

type Status string

const (
	Pending        Status = "pending"
	Running        Status = "running"
	Success        Status = "success"
	Failed         Status = "failed"
	PartialSuccess Status = "partial_success"
	Cancelled      Status = "cancelled"
)

type Task struct {
	ID           string          `json:"id"`
	ProjectID    string          `json:"project_id"`
	Flow         Flow            `json:"flow"`
	Status       Status          `json:"status"`
	CurrentStage string          `json:"current_stage"`
	Input        json.RawMessage `json:"input"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}
type Item struct {
	ID               string          `json:"id"`
	TaskID           string          `json:"task_id"`
	Stage            string          `json:"stage"`
	ItemKey          string          `json:"item_key"`
	Status           Status          `json:"status"`
	Payload          json.RawMessage `json:"payload"`
	Result           json.RawMessage `json:"result,omitempty"`
	Error            sql.NullString  `json:"-"`
	DownstreamTaskID sql.NullString  `json:"-"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
	Attempts         int             `json:"attempts"`
}
type CreateTask struct {
	TaskType        string          `json:"task_type"`
	PipelineProfile string          `json:"pipeline_profile"`
	Input           json.RawMessage `json:"input"`
}
type Completion struct {
	Status Status          `json:"status"`
	Result json.RawMessage `json:"result"`
	Error  string          `json:"error"`
}
type Job struct {
	TaskID string `json:"task_id"`
	ItemID string `json:"item_id"`
}
type Store struct{ DB *sql.DB }

func Open(dsn string) (*Store, error) {
	db, e := sql.Open("sqlite", dsn)
	if e != nil {
		return nil, e
	}
	// SQLite's :memory: database is per connection. One connection keeps unit-test
	// state coherent while file-backed production databases retain WAL concurrency.
	if dsn == ":memory:" {
		db.SetMaxOpenConns(1)
	}
	_, e = db.Exec(`PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,project_id TEXT NOT NULL,flow TEXT NOT NULL,status TEXT NOT NULL,current_stage TEXT NOT NULL,input BLOB NOT NULL,created_at DATETIME NOT NULL,updated_at DATETIME NOT NULL); CREATE TABLE IF NOT EXISTS items(id TEXT PRIMARY KEY,task_id TEXT NOT NULL,stage TEXT NOT NULL,item_key TEXT NOT NULL,status TEXT NOT NULL,payload BLOB NOT NULL,result BLOB,error TEXT,downstream_task_id TEXT,created_at DATETIME NOT NULL,updated_at DATETIME NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,UNIQUE(task_id,stage,item_key)); CREATE INDEX IF NOT EXISTS items_task_status ON items(task_id,status);`)
	if e != nil {
		db.Close()
		return nil, e
	}
	_, _ = db.Exec(`ALTER TABLE items ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0`)
	return &Store{db}, nil
}
func flow(c CreateTask) (Flow, error) {
	p := c.PipelineProfile
	if p == "" {
		p = "default"
	}
	switch {
	case c.TaskType == "binary" && p == "default":
		return Binary, nil
	case c.TaskType == "binary_module" && p == "default":
		return BinaryModule, nil
	case c.TaskType == "source" && p == "default":
		return Source, nil
	case c.TaskType == "source" && p == "kg_source_vuln_scan":
		return KGSource, nil
	}
	return "", fmt.Errorf("unsupported flow %s/%s", c.TaskType, p)
}
func stages(f Flow) []string {
	switch f {
	case Binary:
		return []string{"firmware_unpack", "system_analysis", "binary_to_source", "entry_analysis", "dataflow_vuln_scan"}
	case BinaryModule:
		return []string{"binary_to_source", "entry_analysis", "dataflow_vuln_scan"}
	case Source:
		return []string{"system_analysis", "entry_analysis", "dataflow_vuln_scan"}
	default:
		return []string{"knowledge_graph_entry_fetch", "dataflow_vuln_scan"}
	}
}
func (s *Store) Create(ctx context.Context, pid string, c CreateTask) (Task, error) {
	f, e := flow(c)
	if e != nil {
		return Task{}, e
	}
	if len(c.Input) == 0 {
		c.Input = []byte(`{}`)
	}
	n := time.Now().UTC()
	t := Task{uuid.NewString(), pid, f, Pending, stages(f)[0], c.Input, n, n}
	_, e = s.DB.ExecContext(ctx, "INSERT INTO tasks VALUES(?,?,?,?,?,?,?,?)", t.ID, t.ProjectID, t.Flow, t.Status, t.CurrentStage, t.Input, n, n)
	return t, e
}
func scanTask(r *sql.Row) (Task, error) {
	var t Task
	e := r.Scan(&t.ID, &t.ProjectID, &t.Flow, &t.Status, &t.CurrentStage, &t.Input, &t.CreatedAt, &t.UpdatedAt)
	return t, e
}
func (s *Store) Task(ctx context.Context, id string) (Task, error) {
	return scanTask(s.DB.QueryRowContext(ctx, "SELECT * FROM tasks WHERE id=?", id))
}
func (s *Store) Items(ctx context.Context, id string) ([]Item, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT * FROM items WHERE task_id=? ORDER BY created_at", id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var i Item
		if e = scanItem(rows, &i); e != nil {
			return nil, e
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

type scanner interface{ Scan(...any) error }

func scanItem(row scanner, i *Item) error {
	var result []byte
	if err := row.Scan(&i.ID, &i.TaskID, &i.Stage, &i.ItemKey, &i.Status, &i.Payload, &result, &i.Error, &i.DownstreamTaskID, &i.CreatedAt, &i.UpdatedAt, &i.Attempts); err != nil {
		return err
	}
	i.Result = json.RawMessage(result)
	return nil
}
func terminal(x Status) bool { return x == Success || x == Failed || x == Cancelled }
func key(stage string, p map[string]any, n int) string {
	for _, k := range []string{"function_id", "entry_key", "function_name", "module_key", "firmware_key"} {
		if v, ok := p[k].(string); ok && v != "" {
			return v
		}
	}
	return fmt.Sprintf("%s-%d", stage, n)
}
func children(stage string, r json.RawMessage) []map[string]any {
	var v map[string]json.RawMessage
	if json.Unmarshal(r, &v) != nil {
		return nil
	}
	k := map[string]string{"firmware_unpack": "firmwares", "system_analysis": "modules", "binary_to_source": "modules", "entry_analysis": "entries", "knowledge_graph_entry_fetch": "entries"}[stage]
	var x []map[string]any
	json.Unmarshal(v[k], &x)
	return x
}
func next(f Flow, stage string) string {
	x := stages(f)
	for i, v := range x {
		if v == stage && i+1 < len(x) {
			return x[i+1]
		}
	}
	return ""
}
func (s *Store) insert(ctx context.Context, task, stage, k string, p map[string]any) (*Item, error) {
	b, _ := json.Marshal(p)
	id := uuid.NewString()
	n := time.Now().UTC()
	r, e := s.DB.ExecContext(ctx, "INSERT OR IGNORE INTO items VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", id, task, stage, k, Pending, b, nil, nil, nil, n, n, 0)
	if e != nil || mustRows(r) == 0 {
		return nil, e
	}
	return &Item{ID: id, TaskID: task, Stage: stage, ItemKey: k, Status: Pending, Payload: b}, nil
}
func mustRows(r sql.Result) int64 {
	if r == nil {
		return 0
	}
	n, _ := r.RowsAffected()
	return n
}
func (s *Store) Start(ctx context.Context, id string) ([]Job, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var t Task
	e = tx.QueryRowContext(ctx, "SELECT * FROM tasks WHERE id=?", id).Scan(&t.ID, &t.ProjectID, &t.Flow, &t.Status, &t.CurrentStage, &t.Input, &t.CreatedAt, &t.UpdatedAt)
	if e != nil {
		return nil, e
	}
	if terminal(t.Status) {
		return nil, errors.New("task is terminal")
	}
	var in struct {
		Items []map[string]any `json:"items"`
	}
	json.Unmarshal(t.Input, &in)
	if len(in.Items) == 0 {
		var one map[string]any
		json.Unmarshal(t.Input, &one)
		in.Items = []map[string]any{one}
	}
	var jobs []Job
	for n, p := range in.Items {
		i, e := insertTx(ctx, tx, id, t.CurrentStage, key(t.CurrentStage, p, n), p)
		if e != nil {
			return nil, e
		}
		if i != nil {
			jobs = append(jobs, Job{id, i.ID})
		}
	}
	_, e = tx.ExecContext(ctx, "UPDATE tasks SET status=?,updated_at=? WHERE id=?", Running, time.Now().UTC(), id)
	if e != nil {
		return nil, e
	}
	return jobs, tx.Commit()
}
func (s *Store) Complete(ctx context.Context, taskID, itemID string, c Completion) ([]Job, error) {
	if !terminal(c.Status) {
		return nil, errors.New("completion must be terminal")
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var flow Flow
	var taskStatus Status
	var currentStage, stage string
	var current Status
	e = tx.QueryRowContext(ctx, "SELECT flow,status,current_stage FROM tasks WHERE id=?", taskID).Scan(&flow, &taskStatus, &currentStage)
	if e != nil {
		return nil, e
	}
	e = tx.QueryRowContext(ctx, "SELECT status,stage FROM items WHERE id=? AND task_id=?", itemID, taskID).Scan(&current, &stage)
	if e != nil {
		return nil, e
	}
	if terminal(current) {
		return nil, tx.Commit()
	}
	if _, e = tx.ExecContext(ctx, "UPDATE items SET status=?,result=?,error=?,updated_at=? WHERE id=? AND status NOT IN (?,?,?)", c.Status, c.Result, c.Error, time.Now().UTC(), itemID, Success, Failed, Cancelled); e != nil {
		return nil, e
	}
	var jobs []Job
	if c.Status == Success {
		if ns := next(flow, stage); ns != "" {
			for n, p := range children(stage, c.Result) {
				i, e := insertTx(ctx, tx, taskID, ns, key(ns, p, n), p)
				if e != nil {
					return nil, e
				}
				if i != nil {
					jobs = append(jobs, Job{taskID, i.ID})
				}
			}
			if len(jobs) > 0 {
				if _, e = tx.ExecContext(ctx, "UPDATE tasks SET current_stage=?,status=?,updated_at=? WHERE id=?", ns, Running, time.Now().UTC(), taskID); e != nil {
					return nil, e
				}
				currentStage = ns
			}
		}
	}
	if taskStatus != Cancelled {
		var active, ok, fail int
		rows, e := tx.QueryContext(ctx, "SELECT status,COUNT(*) FROM items WHERE task_id=? GROUP BY status", taskID)
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			var st Status
			var n int
			if e = rows.Scan(&st, &n); e != nil {
				rows.Close()
				return nil, e
			}
			if !terminal(st) {
				active += n
			}
			if st == Success {
				ok += n
			}
			if st == Failed {
				fail += n
			}
		}
		rows.Close()
		if active == 0 {
			final := Success
			if fail > 0 && ok > 0 {
				final = PartialSuccess
			} else if fail > 0 {
				final = Failed
			}
			if _, e = tx.ExecContext(ctx, "UPDATE tasks SET status=?,current_stage=?,updated_at=? WHERE id=? AND status<>?", final, currentStage, time.Now().UTC(), taskID, Cancelled); e != nil {
				return nil, e
			}
		}
	}
	return jobs, tx.Commit()
}
func insertTx(ctx context.Context, tx *sql.Tx, task, stage, k string, p map[string]any) (*Item, error) {
	b, _ := json.Marshal(p)
	id := uuid.NewString()
	n := time.Now().UTC()
	r, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO items VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", id, task, stage, k, Pending, b, nil, nil, nil, n, n, 0)
	if e != nil || mustRows(r) == 0 {
		return nil, e
	}
	return &Item{ID: id, TaskID: task, Stage: stage, ItemKey: k, Status: Pending, Payload: b}, nil
}
func (s *Store) finalize(ctx context.Context, id string) error {
	items, e := s.Items(ctx, id)
	if e != nil {
		return e
	}
	for _, i := range items {
		if !terminal(i.Status) {
			return nil
		}
	}
	ok, fail := 0, 0
	for _, i := range items {
		if i.Status == Success {
			ok++
		}
		if i.Status == Failed {
			fail++
		}
	}
	st := Success
	if fail > 0 && ok > 0 {
		st = PartialSuccess
	} else if fail > 0 {
		st = Failed
	}
	_, e = s.DB.ExecContext(ctx, "UPDATE tasks SET status=?,updated_at=? WHERE id=? AND status<>?", st, time.Now().UTC(), id, Cancelled)
	return e
}
func (s *Store) Cancel(ctx context.Context, id string) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	n := time.Now().UTC()
	if _, e = tx.ExecContext(ctx, "UPDATE tasks SET status=?,updated_at=? WHERE id=?", Cancelled, n, id); e == nil {
		_, e = tx.ExecContext(ctx, "UPDATE items SET status=?,updated_at=? WHERE task_id=? AND status IN (?,?)", Cancelled, n, id, Pending, Running)
	}
	if e != nil {
		return e
	}
	return tx.Commit()
}

// ClaimPending atomically turns a queued item into running work. Several worker Pods
// may race this call; only one gets a row, so no owner lease is required.
func (s *Store) ClaimPending(ctx context.Context, limit int) ([]Item, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT * FROM items WHERE status=? ORDER BY created_at LIMIT ?", Pending, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var i Item
		if err = scanItem(rows, &i); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	for n := range out {
		result, e := tx.ExecContext(ctx, "UPDATE items SET status=?,updated_at=? WHERE id=? AND status=?", Running, time.Now().UTC(), out[n].ID, Pending)
		if e != nil {
			return nil, e
		}
		if mustRows(result) == 0 {
			out[n].ID = ""
		} else {
			out[n].Status = Running
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	claimed := out[:0]
	for _, i := range out {
		if i.ID != "" {
			claimed = append(claimed, i)
		}
	}
	return claimed, nil
}
func (s *Store) DispatchFailed(ctx context.Context, id, msg string) error {
	_, e := s.DB.ExecContext(ctx, "UPDATE items SET status=CASE WHEN attempts+1>=3 THEN ? ELSE ? END,error=?,attempts=attempts+1,updated_at=? WHERE id=? AND status=?", Failed, Pending, msg, time.Now().UTC(), id, Running)
	if e != nil {
		return e
	}
	var taskID string
	if e = s.DB.QueryRowContext(ctx, "SELECT task_id FROM items WHERE id=?", id).Scan(&taskID); e != nil {
		return e
	}
	return s.finalize(ctx, taskID)
}
func (s *Store) RunningItems(ctx context.Context, limit int) ([]Item, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT * FROM items WHERE status=? AND downstream_task_id IS NOT NULL ORDER BY updated_at LIMIT ?", Running, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var i Item
		if e = scanItem(rows, &i); e != nil {
			return nil, e
		}
		out = append(out, i)
	}
	return out, rows.Err()
}
func (s *Store) RecoverUnboundRunning(ctx context.Context, olderThan time.Time, limit int) ([]Item, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT * FROM items WHERE status=? AND downstream_task_id IS NULL AND updated_at<=? ORDER BY updated_at LIMIT ?", Running, olderThan, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var i Item
		if e = scanItem(rows, &i); e != nil {
			return nil, e
		}
		out = append(out, i)
	}
	for _, i := range out {
		if _, e = s.DB.ExecContext(ctx, "UPDATE items SET status=?,updated_at=? WHERE id=? AND status=? AND downstream_task_id IS NULL", Pending, time.Now().UTC(), i.ID, Running); e != nil {
			return nil, e
		}
	}
	return out, rows.Err()
}
func (s *Store) ActiveItems(ctx context.Context, taskID string) ([]Item, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT * FROM items WHERE task_id=? AND status=? AND downstream_task_id IS NOT NULL", taskID, Running)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var i Item
		if e = scanItem(rows, &i); e != nil {
			return nil, e
		}
		out = append(out, i)
	}
	return out, rows.Err()
}
func (s *Store) SetDownstreamTask(ctx context.Context, id, downstream string) error {
	_, e := s.DB.ExecContext(ctx, "UPDATE items SET downstream_task_id=?,updated_at=? WHERE id=?", downstream, time.Now().UTC(), id)
	return e
}
