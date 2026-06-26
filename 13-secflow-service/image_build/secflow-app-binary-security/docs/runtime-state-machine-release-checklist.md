# Runtime State Machine Release Checklist

## Scope
- Service: `13-secflow-service/image_build/secflow-app-binary-security`
- Goal: keep `_apply_task_main_state_update(...)` as the only runtime task main-state write entry
- Non-goals for this release:
  - state_event_inbox redesign
  - DB schema changes
  - cross-repo coordination changes

## Merge Gate
- Run:
  - `python -m py_compile app/service/task/runtime_state.py app/service/task/runtime.py app/service/task/state_machine.py tests/test_task_state_machine.py tests/test_task_manager.py`
  - `PYTHONPATH=. conda run -n sothoth pytest tests/test_task_state_machine.py -q`
  - `PYTHONPATH=. conda run -n sothoth pytest tests/test_task_state_event_inbox_service.py -q`
  - `PYTHONPATH=. conda run -n sothoth pytest tests/test_task_manager.py -k "finalize_task or refresh_task_status_after_sync or running_without_active_lease or requeue_released_running_locked or owned_execution_takeover_requeue_uses_stage_name_for_main_state or stale_execution_keeps_parent_on_current_stage or sync_streaming_task_tail_state" -q`
  - `PYTHONPATH=. conda run -n sothoth pytest tests/test_task_manager.py -k "cancelling or cancel_failed or authoritative_failure or run_task_finally_preserves_tail_runtime_lease or stale_running_streaming_tail_requeues_for_takeover or sync_task_row_lease_view_from_owner_blocks_non_owner or run_task_records_takeover_resume_event_for_streaming_tail" -q`
- Static search checks:
  - no hotspot still does `_set_task_status(...)` and then hand-writes `current_stage`, `runtime_phase`, `finished_at`, `last_error`, or task row lease fields
  - task row lease writes remain only in owner-only lease view sync or lease maintenance paths
- Review checklist:
  - diff clearly separates main-state patch from lease fact sync
  - blocked paths emit `main_state_write_blocked` or `task_row_lease_sync_blocked`
  - non-owner blocked paths do not continue finalize, activate, handoff, or release side effects

## Build Gate
- Use `.github/workflows/build_docker.yaml` as the official image build path
- Confirm:
  - workflow succeeds
  - produced image tag is explicit and traceable to the merge commit
  - image contents match the merged revision
  - at least one fresh worker instance starts successfully in test or staging

## Gray Release Gate
- Replace one `binary-security` worker or API instance first
- Do not roll all replicas at once
- Observation window must include:
  - one newly dispatched task
  - one in-flight task refresh or reconcile cycle
  - one streaming tail path
  - one authoritative failure or cancel recovery path

## Online Validation
- Validate at least:
  - one source task
  - one binary task
  - one task with a tail or failure path
- For each task verify:
  - detail view `status`
  - detail view `current_stage`
  - detail view `runtime_phase`
- Timeline checks:
  - `main_state_write_blocked`
  - `task_row_lease_sync_blocked`
  - `runtime_transition_guard_cleared`
  - `dispatching_state_force_terminalized`
  - `downstream_reconcile_resumed_after_takeover`
- If a read model is available, also verify:
  - `workflow_terminalization_ready`
  - `workflow_blocked_by_stage`

## Log Review
- Inspect:
  - `secflow-app-binary-security`
  - `secflow-app-binary-security-worker`
  - state_event_inbox logs as read-only reference if legacy reducer-compatible telemetry is still present
- Look for:
  - repeated blocked events without later owner progress
  - task row lease sync blocked events on paths that should be owner-owned
  - evidence of finalize, activate, or handoff side effects after blocked main-state writes
  - repair paths modifying state after transition guard clear

## Rollback Triggers
- Tasks remain stuck in `dispatching` or `running` while timeline only shows blocked events
- Cancel recovery or authoritative failure no longer reaches terminal closure
- Task row lease view and runtime lease drift long enough to break stable takeover
- Gray version failure rate is materially worse than the previous stable image

## Rollback Actions
1. Roll deployment image back to the previous stable tag.
2. Preserve affected task ids, timeline snapshots, and pod logs.
3. Do not hand-edit DB rows or runtime lease tables.
4. Recover affected work through existing retry, full retry, or force reset flows.

## Deferred Items
- Remaining low-frequency or control-plane-only direct runtime phase writes can stay deferred if they do not bypass runtime task main-state semantics.
- Any deferred hotspot should be called out in review if it still touches task lifecycle fields.
