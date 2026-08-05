package orchestrator

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestConcurrentClaimsAreUnique(t *testing.T) {
	s, ctx := fresh(t)
	task := makeTask(t, s, CreateTask{TaskType: "source", Input: json.RawMessage(`{"items":[{"module_key":"a"},{"module_key":"b"},{"module_key":"c"},{"module_key":"d"}]}`)})
	s.Start(ctx, task.ID)
	var wg sync.WaitGroup
	var mu sync.Mutex
	count := 0
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			items, e := s.ClaimPending(ctx, 1)
			if e != nil {
				t.Error(e)
				return
			}
			mu.Lock()
			count += len(items)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if count != 4 {
		t.Fatalf("claimed %d items", count)
	}
}

func TestCompletionRollsBackWhenChildInsertFails(t *testing.T) {
	s, ctx := fresh(t)
	task := makeTask(t, s, CreateTask{TaskType: "source", Input: json.RawMessage(`{"items":[{"input_path":"/input"}]}`)})
	root, _ := s.Start(ctx, task.ID)
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_entry BEFORE INSERT ON items WHEN NEW.stage='entry_analysis' BEGIN SELECT RAISE(ABORT,'forced child failure'); END;`); err != nil {
		t.Fatal(err)
	}
	_, err := s.Complete(ctx, task.ID, root[0].ItemID, Completion{Status: Success, Result: json.RawMessage(`{"modules":[{"module_key":"m"}]}`)})
	if err == nil {
		t.Fatal("expected child insertion failure")
	}
	items, err := s.Items(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Status != Pending {
		t.Fatalf("completion leaked across rollback: %#v", items)
	}
	got, _ := s.Task(ctx, task.ID)
	if got.CurrentStage != "system_analysis" || got.Status != Running {
		t.Fatalf("task projection leaked: %#v", got)
	}
}
