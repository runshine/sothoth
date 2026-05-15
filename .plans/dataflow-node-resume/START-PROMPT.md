# Handoff Prompt: Implement Dataflow Node-level Resume

You are implementing a node-level resume mechanism for the SecFlow dataflow vulnerability scanner. Work in repository `/home/icsl/sothoth`.

## Goal

Implement a robust node-level breakpoint/resume flow for `secflow-app-dataflow-vuln-scanner` so the existing frontend “重试 Run” action can continue from the last prompt-level node after network failures, Pod rollback, or killed backend processes, instead of restarting the whole scan.

In this product, a **node** means **one prompt interaction with piagent**. The frontend already has a “会话记录” tab with “最近轮次阶段图”; that graph should become the mental/user-facing model for resume. A node should have stable cycle/phase/step identity, a status, prompt/response trace links, and a deterministic resume policy.

When completing each implementation step below, mark it in your final response with `[DONE:n]` where `n` is the step number.

## Relevant Codebase Context

### Frontend

Frontend root: `/home/icsl/sothoth/13-secflow-service/image_build/secflow-frontend`

Important files:

- `pages/execution/DataflowFileserverRunDashboardPage.tsx`
  - Renders Run detail dashboard.
  - Top action button: `btnRetryRun` labelled “重试 Run”.
  - Current retry logic: `retryCurrentRun()` refreshes current overview, checks `canRetryRun()`, prompts only for `extra_cycles`, calls `retryDataflowFileserverRun(...)`, alerts, reloads.
  - “会话记录” tab:
    - `renderSessions()` renders session viewer plus `renderExecutionTraceOverview()`.
    - `renderExecutionTraceOverview()` shows “最近轮次阶段图”.
    - It builds graph nodes in `buildExecutionTraceModel()` from `current_step`, `step_history`, and fallback session/call data.
    - `getCheckpointExecutionMeta()` maps checkpoint to graph node.
    - `tracePhaseMeta()` maps phases: `worker`, `reflect`, `summary`, `global_review`, `result_review`, `review`, `other`.
    - Prompt previews use `promptUserPath`/`promptSystemPath`; currently these are inferred from runtime calls by `bestPromptSourceForExecutionItem()`.
- `clients/dataflowVulnScanner.ts`
  - API base prefix `/api/dataflow-vuln-scanner`.
  - Existing interfaces: `DataflowRunSummary`, `DataflowRunDetail`, `DataflowRunSession`, `DataflowRunMutationResponse`, `DataflowRunRetryPayload`.
  - Existing API method: `retryRun(runId, payload)` calls `POST /runs/{run_id}/retry`.
- `clients/dataflowVulnRunsFileserver.ts`
  - Wraps `dataflowVulnScannerApi`, resolves run by project/root/name.
  - Existing `retryDataflowFileserverRun(projectId, rootPath, runName, retryPayload)`.

Frontend commands if needed:

```bash
cd /home/icsl/sothoth/13-secflow-service/image_build/secflow-frontend
npm run lint
npm run build
```

### Backend service

Backend root: `/home/icsl/sothoth/13-secflow-service/image_build/secflow-app-dataflow-vuln-scanner`

Important files:

- `app/api/tasks.py`
  - Router prefix `/api/dataflow-vuln-scanner`.
  - Existing `POST /runs/{run_id}/retry` calls `ExecutionService.retry_run()` and queues execution.
- `app/schemas.py`
  - Existing `RunRetryRequest`: `extra_cycles`, `model`, `provider`, `clean_workspace`.
  - Existing `RunMutationResponse`: `success`, `run_id`, `project_id`, `status`, `message`, linked ids, process fields.
  - Existing `RunDetailResponse` includes `current_step`, `step_history`, `cycle_timing`, `raw`.
- `app/services/execution_service.py`
  - Existing `retry_run()` flow:
    1. load/refresh `RunIndex`;
    2. inspect linked trigger/execution;
    3. compute `process_state = _run_process_state(...)`;
    4. reject if `can_retry` false;
    5. `_preflight_run_resume(run_index, payload)`;
    6. mark stale runtime exited;
    7. create new execution attempt with request from `_build_run_index_resume_request()`;
    8. bind run status `queued` and record `run_resume_queued` event.
  - Existing `_preflight_run_resume()` imports `run_vuln_scan` and `app.pi_vuln_core.resume`, calls `build_resume_plan()` and `rebuild_review_state()`, writes `_meta/resume_preview.json`, returns a dict with `preview_path`, `resume_cursor`, `resume_target_node`, `node_resume_policy`, etc.
  - Existing `_build_dataflow_cli_argv()` emits `--resume-run-dir <run_dir> --extra-cycles <n>` for resume requests.
  - Existing `_run_process_state()` has stale/active retryability logic. Reuse it; do not introduce duplicate process-state models unless necessary.
- `run_vuln_scan.py`
  - CLI supports `--resume-run-dir`, `--extra-cycles`, `--dry-run-resume`.
  - Resume path calls `build_resume_plan()`, writes `_meta/resume_preview.json`, then `resume_run()`.
  - `_write_resume_preview_file()` already accepts fields such as `resume_cursor`, `resume_target_node`, `node_resume_policy`.
- `app/pi_vuln_core/engine/checkpoint.py`
  - Existing file-based checkpoint helpers:
    - `record_step_checkpoint(work_dir, cycle, phase, step_key, status, agent_id='', session_id='', detail='', extra=None)`.
    - `load_step_checkpoint(...)`, `load_step_checkpoints(...)`, `load_current_checkpoint(...)`.
    - Files are stored under `<atomic_work_dir>/_meta/checkpoints/current_step.json` and `steps/cycle_XXX/<phase>/<safe_step_key>.json`.
    - Terminal statuses: `completed`, `partial_salvaged`, `soft_failed`.
  - This is the correct durable foundation because it lives in the run workspace, not only in process memory or DB.
- `app/pi_vuln_core/resume.py`
  - Existing `build_resume_plan(run_dir)` reads config, discovers atomic work dir, completed cycles, worker session, current status, current/historical checkpoint.
  - Existing `_build_resume_cursor()` is step-level: non-terminal current checkpoint => rerun same phase/step; terminal => compute next node in `_next_node_after_checkpoint()`.
  - Existing `resume_run()` calls `AtomicWorkflowEngine.resume_from_existing(... resume_cursor=plan.resume_cursor ...)`.
- `app/pi_vuln_core/engine/atomic.py`
  - Existing `resume_from_existing()` builds `WorkflowContext` and calls `_run_review_cycles(... resume_cursor=...)`.
  - `_run_review_cycles()` uses phase order and `resume_cursor` to skip phases before target phase.
  - It passes `active_resume_cursor` to WorkerExecutor and ReviewScheduler.
- `app/pi_vuln_core/engine/worker.py`
  - Records checkpoints for:
    - worker main/rework (`worker::work`, `worker::rework`),
    - staged rework (`worker::rework_triage`, `worker::rework_fp_repair`, `worker::rework_missed_hunt`, `worker::rework_handoff`),
    - reflection (`reflect::<prompt_id>::pass_XX`),
    - summary (`summary`).
  - Uses `load_step_checkpoint()` and `is_terminal_checkpoint()` to skip completed nodes on resume.
  - `AgentResponse.metadata` from pi_agent includes `call_dir` on success/failure, but most checkpoints currently do not persist that field.
- `app/pi_vuln_core/review/global_review.py`
  - Records checkpoints for each global advisor currently using `step_key=f"global::{advisor_def.instance_id}"`.
  - `_parse_with_schema_repair()` sends additional repair prompts but does not checkpoint each repair prompt as a separate node.
- `app/pi_vuln_core/review/result_review.py`
  - Records checkpoints for result/advisor using `step_key=f"result::{result_file}::{advisor_def.instance_id}"`.
  - `_parse_with_schema_repair()` sends additional repair prompts but does not checkpoint each repair prompt as a separate node.
  - Result review may run in parallel; maintain deterministic ordering for planning.
- `app/pi_vuln_core/agents/runtime_trace.py`
  - `RuntimeTraceContext` writes per-call artifacts under `sessions/<session_id>/calls/<turn>_<uuid>/`: `request.json`, `response.json`, `user_prompt.md`, `system_prompt.md`, stdout/stderr, heartbeat.
- `app/pi_vuln_core/agents/runtimes/pi_agent.py`
  - `send_message()` creates `RuntimeTraceContext`; returned `AgentResponse.metadata` includes `call_dir`, `mode`, output stats, timeout info, event counts.
  - Runtime timeout retries are stored as `attempts` inside one call trace. Treat these as attempts of the same prompt node, not separate nodes, unless the code creates a new user prompt.
- `app/services/run_inspector.py`
  - `inspect_run_detail()` exposes `current_step`, `step_history`, `cycle_timing` from `_meta/checkpoints`.
  - `inspect_sessions()` exposes runtime call traces and prompt file paths to frontend.
- `app/services/run_index_service.py`
  - Syncs inspector output into DB `RunIndex.raw_summary_json` and session rows.
  - `get_run_detail()` returns `current_step`, `step_history`, `cycle_timing`, `sessions`.

Backend commands if needed:

```bash
source /home/runshine/miniconda3/etc/profile.d/conda.sh && conda activate sothoth
cd /home/icsl/sothoth/13-secflow-service/image_build/secflow-app-dataflow-vuln-scanner
pytest tests/test_resume_convergence_consistency.py
pytest tests/test_dataflow_service_api.py tests/test_scheduler_recovery_api.py
```

## Critical Design Rules / Gotchas

1. **Do not replace the existing checkpoint/resume foundation.** Extend `checkpoint.py`, `resume.py`, and existing executors so older runs remain recoverable.
2. **A prompt node must be durable before the prompt is sent.** Record `started` first, then update terminal status after response/validation.
3. **Prompt trace links should be explicit.** After `AgentResponse` returns, persist `metadata.call_dir`, `turn_count`, and prompt/response paths into the checkpoint so the frontend does not need heuristic prompt matching.
4. **Schema repair prompts are prompt interactions.** They must become nodes or explicitly declare `resume_policy=rerun_parent_node`. Prefer making repair prompts self-contained by embedding/truncating the invalid prior output, so they can be safely rerun after Pod rollback.
5. **Runtime timeout retries are attempts of one node.** `pi_agent.py` already stores retry `attempts` in `response.json`; do not create duplicate graph nodes for internal retry of the same prompt unless a new prompt is actually sent.
6. **Review nodes are read-only; Worker/summary nodes write artifacts.** For review, skip only if valid review JSON exists and is not `agent_error` / `ERROR` / read-only violation. For worker/summary, record artifact digests and be conservative; do not delete partially written artifacts automatically.
7. **Result review parallelism requires stable planning order.** Sort by result file then advisor definition order for planning. After target selection, remaining pending nodes may still run with configured concurrency.
8. **Frontend must show what will resume.** The user should see target cycle/phase/step/status/policy before confirming “重试 Run”.
9. **No DB migration should be necessary for checkpoint details.** New node fields can remain in JSON files and `raw_summary_json`; only Pydantic/TypeScript response models need optional fields.
10. **Backward compatibility:** old step keys (`worker`, `global::<advisor>`, `result::<file>::<advisor>`) must still load and skip correctly.

## Implementation Plan

### Step 1 — Extend checkpoint schema and helpers

Modify `app/pi_vuln_core/engine/checkpoint.py`.

- Add helper(s):
  - `build_node_id(cycle, phase, step_key) -> str`.
  - `checkpoint_prompt_paths_from_call_dir(call_dir, work_dir) -> dict` to derive relative `user_prompt.md`, `system_prompt.md`, `request.json`, `response.json` if present.
  - Optional `merge_checkpoint_runtime_trace(checkpoint, response_metadata, work_dir)`.
- Extend `record_step_checkpoint()` parameters with optional backward-compatible args such as:
  - `node_id`, `parent_node_id`, `resume_policy`, `call_dir`, `turn_count`, `prompt_user_path`, `prompt_system_path`, `prompt_request_path`, `prompt_response_path`, `artifact_digest_before`, `artifact_digest_after`.
- Existing callers must still work without changes.
- Preserve file layout under `_meta/checkpoints/`.
- Add fields to payload only when present.

Mark complete with `[DONE:1]`.

### Step 2 — Persist runtime call trace info for existing Worker/reflection/summary nodes

Modify `app/pi_vuln_core/engine/worker.py`.

- For worker main/rework and staged rework:
  - Keep existing `started` checkpoint before sending prompt.
  - On terminal checkpoint, include `call_dir=response.metadata.get("call_dir")`, `turn_count=response.turn_count`, `internal_turn_count`, `event_total_count`, and prompt/response paths derived from call_dir.
  - For worker/summary artifact-writing nodes, compute digest before/after using existing `_worker_editable_artifact_digest(ctx)` where appropriate; store in checkpoint `extra` or top-level optional fields.
- For reflection and summary:
  - Same pattern: terminal checkpoint includes `call_dir`, `turn_count`, prompt/response paths.
  - Reflection `soft_failed` remains terminal.
- Ensure existing skip behavior based on `is_terminal_checkpoint(load_step_checkpoint(...))` remains compatible.

Mark complete with `[DONE:2]`.

### Step 3 — Add node checkpoints for schema repair prompts

Modify `app/pi_vuln_core/review/global_review.py` and `app/pi_vuln_core/review/result_review.py`.

- For initial global/result advisor prompt, continue using the existing parent step key for backward compatibility:
  - global parent: `global::<advisor>`
  - result parent: `result::<result_file>::<advisor>`
- In `_parse_with_schema_repair()`:
  - Add parameters needed for checkpointing: `work_dir`, `cycle`, `advisor_def` or `advisor_id`, and parent step key.
  - Before each `agent.send_message(repair_prompt, ...)`, record a repair node `started` checkpoint:
    - global: `global::<advisor>::repair_<NN>`
    - result: `result::<result_file>::<advisor>::repair_<NN>`
    - `parent_node_id` points to parent advisor node.
  - After repair response, record `completed` or `failed` with call trace fields.
- Make repair prompt self-contained:
  - Include the invalid prior output (truncate to a safe size, e.g. 16–64KB) or enough raw content in the repair prompt.
  - If not self-contained, set `resume_policy="rerun_parent_node"` for repair node and make planner honor it.
- Keep final parent advisor checkpoint `completed/failed` after the whole parse/write-review-record operation, so old logic still sees the parent node terminal.

Mark complete with `[DONE:3]`.

### Step 4 — Build deterministic node ordering and NodeResumePlan

Modify `app/pi_vuln_core/resume.py`.

- Introduce a small internal model/dict for `NodeResumePlan` or extend `ResumePlan` fields.
- Build deterministic node sequence for a cycle:
  1. worker node(s): `worker::work` or rework/staged rework based on existing context and config;
  2. reflection nodes from configured prompts and passes;
  3. summary node;
  4. global review advisors that are active in that cycle;
  5. result review nodes from current result files and configured result advisors.
- Upgrade `_build_resume_cursor()`:
  - If current checkpoint is non-terminal and cycle > completed cycles: target current node.
  - If current checkpoint is terminal and cycle > completed cycles: target the next node in deterministic order.
  - If current checkpoint is from a completed cycle (`cycle <= completed_cycles`): start after completed cycles.
  - If target node has `resume_policy=rerun_parent_node`, target parent node.
- Ensure `resume_start_cycle` is `target_cycle - 1` when resuming within an incomplete current cycle.
- Include in cursor:
  - `target_node_id`, `cycle`, `phase`, `step_key`, `node_kind`, `status`, `policy`, `source`, `completed_node_count`, `skipped_node_count`.
- Keep old fields `resume_target_phase`, `resume_target_step_key`, `checkpoint_*` populated for UI/backcompat.

Mark complete with `[DONE:4]`.

### Step 5 — Make executors honor node-level cursor

Modify `app/pi_vuln_core/engine/atomic.py`, `app/pi_vuln_core/engine/worker.py`, `app/pi_vuln_core/review/global_review.py`, `app/pi_vuln_core/review/result_review.py`.

- Keep phase skipping in `AtomicWorkflowEngine._run_review_cycles()` but treat `resume_cursor` as node-level.
- Implement or reuse helper: `should_skip_node(work_dir, cycle, phase, step_key, resume_cursor, validate_artifact=True)`.
- Worker/reflection/summary:
  - Already skip terminal checkpoints. Ensure target node reruns when checkpoint is non-terminal or invalid.
- Global review:
  - Skip valid existing review records.
  - Run missing/invalid advisor nodes in stable advisor order.
  - If cursor targets a specific global/repair node, do not run logically earlier missing nodes unless they are required parent context; if a required parent is missing, planner should target parent.
- Result review:
  - Build pending node list in deterministic order: result filename order then advisor order.
  - Skip terminal valid review records.
  - If cursor targets a result/advisor or repair node, run from that point onward. After filtering, parallel execution may still be used for remaining nodes.
- Maintain old behavior for old runs that only have parent step checkpoints.

Mark complete with `[DONE:5]`.

### Step 6 — Handle partial artifacts and invalid review records safely

Modify relevant worker/review executors and resume planner.

- Worker/summary:
  - Store artifact digest before and after node.
  - On resume of non-terminal worker/summary node, do not automatically delete `summary.md`, `results/`, `supporting_docs/`. Mark prior attempt as aborted in checkpoint extra/history and rerun with existing artifacts so the prompt can reconcile.
- Review nodes:
  - Keep existing invalid-record rules: `parser_mode == "agent_error"` or `verdict == "ERROR"` means not valid terminal output.
  - Also treat read-only violation records as invalid for skip.
  - If a partial JSON file exists but is invalid, ignore or overwrite on rerun.

Mark complete with `[DONE:6]`.

### Step 7 — Expose backend resume preview and response fields

Modify `app/schemas.py`, `app/api/tasks.py`, `app/services/execution_service.py`.

- In `schemas.py`:
  - Add `RunResumePlanResponse` with fields from `_preflight_run_resume()`.
  - Extend `RunMutationResponse` with optional `resume_preflight: Dict[str, Any] = Field(default_factory=dict)` or `Optional[Dict[str, Any]]`.
- In `tasks.py`:
  - Add endpoint, for example:
    - `POST /runs/{run_id}/resume-preview` with `RunRetryRequest` body.
    - It should check project access via `_run_index_or_404()` in service and call a new service method `preview_run_resume(...)`.
- In `execution_service.py`:
  - Add `preview_run_resume(db, run_index_id, principal, payload)` wrapping `_preflight_run_resume()` and `process_state` without queuing.
  - In `retry_run()`, include the same preflight dict in returned mutation response.
  - Keep duplicate resume prevention via `process_state.can_retry`; if an execution is already pending/queued/dispatching, preview can still show state but retry must reject.

Mark complete with `[DONE:7]`.

### Step 8 — Ensure inspector/index exposes new node fields

Modify `app/services/run_inspector.py` and `app/services/run_index_service.py`.

- `run_inspector._load_current_step_checkpoint()` / `_collect_step_checkpoints()` should pass through new fields (`node_id`, `parent_node_id`, `resume_policy`, `call_dir`, prompt paths, artifact digests, etc.).
- `_collect_cycle_timing()` should continue working with new fields.
- `run_index_service._raw_summary_db_view()` may summarize new current step fields if needed, but avoid externalizing excessive prompt content into DB.
- Ensure `resume_preview.json` is visible through file listing (`inspect_files`) as a Meta file, if not already.

Mark complete with `[DONE:8]`.

### Step 9 — Update frontend API types and wrappers

Modify frontend files:

- `clients/dataflowVulnScanner.ts`:
  - Add `DataflowRunResumePlan` interface matching backend preview.
  - Extend `DataflowRunMutationResponse` with `resume_preflight?: DataflowRunResumePlan | Record<string, any>`.
  - Add `previewRunResume(runId, payload)` calling `POST /runs/{run_id}/resume-preview`.
- `clients/dataflowVulnRunsFileserver.ts`:
  - Add `previewRetryDataflowFileserverRun(projectId, rootPath, runName, retryPayload)` resolving run then calling `previewRunResume()`.

Mark complete with `[DONE:9]`.

### Step 10 — Replace simple retry prompt with resume preview confirmation UI

Modify `pages/execution/DataflowFileserverRunDashboardPage.tsx`.

- Replace `retryCurrentRun()` flow:
  1. Refresh latest run overview with `inspectDataflowFileserverRunOverview(..., { force: true })`.
  2. Check `canRetryRun()`.
  3. Ask for or show an input for `extra_cycles` (modal preferred; a prompt is acceptable for MVP but must fetch preview before final confirm).
  4. Call `previewRetryDataflowFileserverRun(...)`.
  5. Show target details before submitting:
     - target cycle, phase label, humanized step label,
     - source checkpoint status,
     - `resume_policy`,
     - completed cycles, start cycle, total cycle limit,
     - preview path and command if available,
     - warnings about partial worker/summary artifacts if present.
  6. On confirm, call `retryDataflowFileserverRun(...)`.
  7. Display returned `resume_preflight` and reload current run.
- Add helper methods to render a resume plan using existing phase/step label functions (`tracePhaseMeta()`, `humanizeTraceStepKey()`).
- Keep graceful fallback: if preview endpoint is missing/fails due to older backend, show error and do not submit blindly unless explicitly desired.

Mark complete with `[DONE:10]`.

### Step 11 — Enhance recent phase graph with explicit resume target / prompt paths

Modify `DataflowFileserverRunDashboardPage.tsx`.

- `getCheckpointExecutionMeta()` should consume new fields:
  - `node_id`, `resume_policy`, `call_dir`, `prompt_user_path`, `prompt_system_path`, `prompt_request_path`, `prompt_response_path`.
- `renderExecutionPromptPreview()` should prefer explicit prompt paths from checkpoint over heuristic matching.
- If a resume preview is loaded or `current_step` is stale/non-terminal, add a badge/class to the matching node: “恢复点” / “将从此节点重跑”.
- Preserve old behavior for old runs: if no explicit prompt path exists, continue using `bestPromptSourceForExecutionItem()`.

Mark complete with `[DONE:11]`.

### Step 12 — Add tests

Backend tests:

- Extend or add tests near `tests/test_resume_convergence_consistency.py`:
  - checkpoint `started` at cycle 2 global advisor => `build_resume_plan()` targets same node and `resume_start_cycle == 1`.
  - checkpoint `completed` at cycle 2 summary => target first global review node.
  - completed cycle summary exists => target next cycle worker.
- Add schema repair interruption test:
  - Mock advisor returns invalid JSON, then simulate interruption during repair node; after resume, it should rerun repair node (or parent if `resume_policy=rerun_parent_node`) and produce valid review.
- API test:
  - Use test client to call `/runs/{run_id}/resume-preview` and assert target node fields.
  - Verify retry response includes `resume_preflight`.
  - Verify duplicate queued resume is rejected.

Frontend/tests:

- Run `npm run lint` after type changes.
- If there are existing frontend tests/contracts, add a lightweight assertion that client exposes preview and retry response accepts `resume_preflight`.

Mark complete with `[DONE:12]`.

### Step 13 — Document compatibility and behavior

Add/update docs under backend `docs/` or README:

- Explain node definition: one piagent prompt interaction, with timeout retries as attempts.
- Explain statuses and resume policy.
- Explain what “重试 Run” does after Pod rollback/stale runtime.
- Explain old-run fallback and limitations.

Mark complete with `[DONE:13]`.

## Validation Checklist

After implementing, run as much as practical:

```bash
source /home/runshine/miniconda3/etc/profile.d/conda.sh && conda activate sothoth
cd /home/icsl/sothoth/13-secflow-service/image_build/secflow-app-dataflow-vuln-scanner
pytest tests/test_resume_convergence_consistency.py
pytest tests/test_dataflow_service_api.py tests/test_scheduler_recovery_api.py

cd /home/icsl/sothoth/13-secflow-service/image_build/secflow-frontend
npm run lint
```

If full tests are too slow/unavailable, run targeted tests and document what was not run.

## Expected Final Response Format

In your final response, summarize changes and include done markers, for example:

- `[DONE:1]` Extended checkpoint schema ...
- `[DONE:2]` Persisted runtime call trace fields ...
- ...
- Tests run: ...

If any step cannot be completed, explain why and what remains.
