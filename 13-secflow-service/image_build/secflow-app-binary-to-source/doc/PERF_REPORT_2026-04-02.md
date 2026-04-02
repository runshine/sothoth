# secflow-app-binary-to-source Perf Report (2026-04-02)

## Scope
- Environment: current `secflow-ns` K8s cluster
- Project name: `abbbb`
- Project ID: `7518fc540de52fbe`
- API target: `/api/app/binary-to-source`
- Worker setting: `WORKER_CONCURRENCY=4`, `WORKER_POOL=prefork`

## Fixes Included
- Commit: `a6fdc46`
- Key changes:
  - Reset SQLAlchemy engine/session per prefork child process.
  - `expire_on_commit=False` and DB pool hardening (`pool_recycle`).
  - Atomic claim in worker (`queued/pending -> running`) to avoid duplicate task execution.
  - Explicit rollback in exception path before fallback updates.
  - Atomic claim in scheduler (`pending -> queued`) before Celery publish.
  - Fast recovery for queued items targeting offline workers.

## Baseline Results (After Fix)

### API Create Latency
- Sample count: 10
- Avg: 104.6 ms
- P50: 102 ms
- P95: 118 ms
- Min/Max: 97 / 123 ms

### 12-ELF Task (3 runs)
- Run1: create 110 ms, complete 2 s, throughput 6.00 items/s
- Run2: create 112 ms, complete 4 s, throughput 3.00 items/s
- Run3: create 124 ms, complete 2 s, throughput 6.00 items/s
- All runs: `completed`, `12/12 success`, `queued=0`

### 120-ELF Task (2 runs)
- Run1: create 136 ms, complete 17 s, throughput 7.06 items/s
- Run2: create 189 ms, complete 17 s, throughput 7.06 items/s
- Both runs: `completed`, `120/120 success`, `queued=0`

### 300-ELF Task (1 run)
- Create 188 ms, complete 45 s, throughput 6.67 items/s
- Result: `completed`, `300/300 success`, `queued=0`

### Resource Snapshot During Large Runs
- `cpu_sum_m` observed up to ~585m across binary-to-source manager+worker pods
- `mem_sum_Mi` observed up to ~1556Mi across binary-to-source manager+worker pods

## Before/After Comparison (Key Risk)

### Before Fix (observed on same day)
- Large tasks could stall at tail:
  - Example: 60 task stuck near `51/60` with `queued>0` and `running=0`
  - Example: 120 task stuck near `80/120`
- Worker logs showed DB/session concurrency errors:
  - `StaleDataError`
  - `PendingRollbackError`
  - `Command Out of Sync`
  - `MySQL server has gone away`

### After Fix
- 120/300 tasks finished to terminal success without queue tail stall.
- No new occurrences of above DB/session concurrency errors in recent worker logs during test window.

## Conclusion
- The concurrency/session stability issue that previously blocked large tasks is mitigated in this version.
- Current practical capacity baseline (this cluster):
  - Sustained throughput around **6.6~7.1 items/s** for 120~300 sized workloads.
- Recommend next step:
  - Run mixed workloads (success/partial/fail/cancel) at 500+ ELF to verify long-run stability and SLO.
