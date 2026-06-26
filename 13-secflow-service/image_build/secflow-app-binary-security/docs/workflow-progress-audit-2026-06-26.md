# Binary Security Workflow Progress Audit

## Scope

This document captures the current static workflow audit for `binary-security` after the reducer-to-owner migration work. It is intended to be the baseline for:

- further owner-path refactors
- broad E2E validation
- rollout acceptance
- live timeline review against intended design

Audit date: `2026-06-26`

## Canonical Task Types And Stage Sequences

Source of truth:
- [app/model.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/model.py:45)
- [app/service/task_manager.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task_manager.py:3094)

### 1. `binary`

Sequence:
- `firmware_unpack`
- `system_analysis`
- `binary_to_source`
- `entry_analysis`
- `dataflow_vuln_scan`

### 2. `source` default profile

Sequence:
- `system_analysis`
- `entry_analysis`
- `dataflow_vuln_scan`

### 3. `source` KG profile

Sequence:
- `knowledge_graph_entry_fetch`
- `dataflow_vuln_scan`

### 4. `binary_module`

Sequence:
- `binary_to_source`
- `entry_analysis`
- `dataflow_vuln_scan`

## Intended Long-Term Progress Semantics

The intended design being audited against is:

- owner worker is the single normal control plane
- reducer/state-event inbox is legacy compatibility only
- next-stage start must be owner-decided
- upstream archive success and postprocess completion are authoritative
- streaming may seed downstream items incrementally
- streaming must not create empty downstream stage runs in advance
- a stage run should mean real work exists or has materially existed

## Current Static Code Findings

## A. Common Start Gates

Primary gate helpers:
- [app/service/task_manager.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task_manager.py:8202)
- [app/service/task_manager.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task_manager.py:8226)
- [app/service/task/state_machine.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/state_machine.py:2025)
- [app/service/task/runtime.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/runtime.py:2365)

Current behavior:
- `_stage_start_ready(...)` allows stage start only when real runnable work exists or materialized inputs exist.
- `_should_auto_advance_to_stage(...)` already blocks `dataflow_vuln_scan` when `entry_analysis` has no archived-success progress.
- `_stage_has_materialized_inputs(...)` delegates to stage handlers for authoritative input readiness.

Assessment:
- broadly aligned with the target direction
- no obvious normal-path evidence that a downstream stage starts with zero runnable/materialized inputs through the main owner loop

## B. Archive Success Gates

Primary helpers:
- [app/service/task_manager.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task_manager.py:7028)
- [app/service/task_manager.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task_manager.py:7075)
- [app/service/task/state_machine.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/state_machine.py:2250)

Current behavior:
- `firmware_unpack`, `system_analysis`, `binary_to_source`, `entry_analysis` all require archive-success gating.
- stage terminal handling explicitly stops progression when business success has happened but archive success is still missing.
- `dataflow_vuln_scan` does not itself require archive-success gating as an upstream barrier stage.

Assessment:
- aligned with “must wait for upstream archive success before downstream progression”
- this is one of the strongest parts of the current implementation

## C. Workflow Finalization / Fake Active Stage Protection

Primary helpers:
- [app/service/task/state_machine.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/state_machine.py:682)
- [app/service/task/state_machine.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/state_machine.py:198)
- [app/service/task/state_machine.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/state_machine.py:3749)

Current behavior:
- workflow snapshots track:
  - `has_stage_run`
  - `item_count`
  - `has_active_items`
  - `has_materialized_inputs`
  - `has_unresolved_expected_outputs`
- `_stage_snapshot_is_shell_active(...)` treats empty active shells specially and prevents them from being treated as real active work in several critical paths.
- finalize gate now distinguishes real active work from empty stage shells much better than earlier revisions.

Assessment:
- aligned with the user’s requirement to stop empty stage projections from keeping tasks falsely alive
- still needs follow-through in all stage-run creation paths

## D. Owner-Direct Fact Apply

Primary helpers:
- [app/service/task/owner_fact_apply.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/owner_fact_apply.py:1)
- [app/service/task/runtime.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/runtime.py:2380)

Current behavior:
- owner loop now builds inline state events and directly applies:
  - `stage_worker_start_requested`
  - `stage_worker_terminal_observed`
- normal downstream sync application is no longer reducer-owned.
- reducer inbox consumption is hard-disabled for normal runtime use.

Assessment:
- strongly aligned with the migration goal
- normal control plane has already largely moved to owner execution

## Workflow-Type Audit

## 1. `source` Default: `system_analysis -> entry_analysis -> dataflow_vuln_scan`

### `system_analysis -> entry_analysis`

Relevant code:
- [app/service/stages/system_analysis.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/stages/system_analysis.py:22)
- [app/service/task/contracts.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/contracts.py:454)
- [app/service/task_manager.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task_manager.py:10020)
- [app/service/task/state_machine.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/state_machine.py:1622)

Observed semantics:
- `system_analysis` authoritative completion requires stage success-like status and `selected_modules` already refreshed into summary.
- `entry_analysis` inputs for source are built from `selected_modules`, and where possible merged with archived authoritative module data.
- source entry progression is blocked until `system_analysis` archived-success progress exists.

Assessment:
- aligned with “system_analysis must archive and postprocess before entry_analysis starts”

### `entry_analysis -> dataflow_vuln_scan`

Relevant code:
- [app/service/stages/entry_analysis.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/stages/entry_analysis.py:14)
- [app/service/stages/dataflow_vuln_scan.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/stages/dataflow_vuln_scan.py:14)
- [app/service/task/state_machine.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/state_machine.py:2037)
- [app/service/task/state_machine.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/state_machine.py:2350)
- [app/service/task_manager.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task_manager.py:8238)

Observed semantics:
- `dataflow_vuln_scan` start is blocked when `entry_analysis` has no archived-success progress.
- `dataflow_vuln_scan` input readiness depends on effective entry inputs and entry authoritative readiness.
- missing entry results can terminalize the path instead of leaving DFS permanently waiting.

Assessment:
- largely aligned
- strongest remaining mismatch is not the barrier itself, but who is allowed to create the first `dataflow_vuln_scan` stage run

## 2. `binary`: `firmware_unpack -> system_analysis -> binary_to_source -> entry_analysis -> dataflow_vuln_scan`

### `system_analysis -> binary_to_source`

Relevant code:
- [app/service/stages/binary_to_source.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/stages/binary_to_source.py:14)
- [app/service/task/state_machine.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/state_machine.py:1633)

Observed semantics:
- `binary_to_source` inputs come from `selected_modules`
- progression is blocked until `system_analysis` archived-success progress exists

Assessment:
- aligned

### `binary_to_source -> entry_analysis`

Relevant code:
- [app/service/task/contracts.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/contracts.py:483)
- [app/service/task_manager.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task_manager.py:10045)
- [app/service/task/state_machine.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/state_machine.py:1643)

Observed semantics:
- non-source entry inputs are rebuilt from archived-success `binary_to_source` payload rows
- `entry_analysis` is blocked until `binary_to_source` archived-success progress exists

Assessment:
- aligned

### `entry_analysis -> dataflow_vuln_scan`

Same conclusions as source default:
- archive-success and materialized-input gates are present
- first-stage-run creation path still needs tightening

## 3. `binary_module`: `binary_to_source -> entry_analysis -> dataflow_vuln_scan`

Relevant code:
- [app/service/stages/entry_analysis.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/stages/entry_analysis.py:27)
- [app/service/task/contracts.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/contracts.py:483)

Observed semantics:
- `entry_analysis` requires `b2s_results`
- for `binary_module`, `entry_descriptor_ready` and descriptor file presence are explicitly required
- `dataflow_vuln_scan` still depends on authoritative entry results

Assessment:
- aligned with the intended stricter binary-module contract

## 4. `source` KG Profile: `knowledge_graph_entry_fetch -> dataflow_vuln_scan`

Relevant code:
- [app/service/stages/knowledge_graph_entry_fetch.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/stages/knowledge_graph_entry_fetch.py:14)
- [app/service/task_manager.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task_manager.py:11600)
- [app/service/task_manager.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task_manager.py:7075)

Observed semantics:
- KG stage is effectively stage-level, not fanout-level
- it writes authoritative `entry_results`
- archive success is virtualized as success only when authoritative success payload exists
- downstream DFS start still depends on effective entry inputs becoming available

Assessment:
- generally aligned with intended KG semantics
- still shares the generic downstream stage-run creation concerns

## Confirmed Mismatches / Residual Risk Areas

## M1. Streaming seed helpers still create stage runs directly

Code:
- [app/service/task/downstream.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/downstream.py:215)
- [app/service/task/downstream.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/downstream.py:279)
- [app/service/task/downstream.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/downstream.py:364)

What happens now:
- once an upstream archived-success result is applied inline, the streaming helper:
  - calls `_ensure_stage_run(...)`
  - upserts downstream stage items
  - records streaming seeded events

Why this is only partially acceptable:
- with the current schema, stage items require non-null `stage_run_id`, so first-item materialization cannot avoid creating a stage run
- however, this should only happen when a real item is being materialized by the owner path
- the helper must not become a generic “future stage activation” shortcut

Required direction:
- keep “first real item materialization may create the stage run”
- remove any path where stage runs are created without real item materialization
- ensure only owner-authoritative paths do this

## M2. Compatibility event paths still create stage runs

Code:
- [app/service/task/state_event_inbox.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/state_event_inbox.py:46)
- [app/service/task/owner_fact_apply.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/owner_fact_apply.py:267)

What happens now:
- compat event application still creates stage runs when stage terminal/start facts arrive

Risk:
- even though reducer normal consumption is disabled, legacy paths still preserve the old “event arrives -> stage run appears” mental model

Required direction:
- further reduce compat paths
- prefer owner-synchronous application where possible
- leave compat paths only as historical fallback

## M3. `_ensure_stage_inputs_available(...)` still mixes input repair with activation-adjacent behavior

Code:
- [app/service/task_manager.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task_manager.py:9884)

What happens now:
- helper may:
  - refresh upstream summary from authoritative items
  - rebuild `b2s_results`
  - rebuild `entry_results`
  - rebuild missing `entry_analysis` authoritative items

Risk:
- this is useful as self-heal
- but it is close enough to stage activation that it can blur the line between:
  - “repair existing authoritative truth”
  - “start a new stage”

Required direction:
- keep self-heal
- move toward explicit owner-only repair phases/signals
- avoid hiding stage activation inside generic input-availability calls

## M4. Failure-only paths still create stage runs for bookkeeping

Code:
- [app/service/task/state_machine.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/state_machine.py:460)

What happens now:
- some authoritative failure or missing-result paths still `_ensure_stage_run(...)` to attach failure context

Risk:
- less harmful to progression than M1/M2
- but can still pollute stage timeline/read model with runs that were never truly executed

Required direction:
- audit whether these should remain as explicit failure projections
- if retained, they should be clearly treated as terminal projection rows, not executable stage activations

## Reducer Migration Status

Static conclusion:
- reducer is no longer the normal control plane
- owner loop already performs the main stage start / stage terminal / downstream fact apply path inline
- remaining reducer pieces are compat shell, metrics shell, and historical queue plumbing
- `TaskManager.start()` no longer starts the legacy `state_event_inbox` loops; the handles remain in the manager only for shutdown compatibility and read-model/metrics surface cleanup

Primary evidence:
- [app/service/task_manager.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task_manager.py:1026)
- [app/service/task/runtime.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/runtime.py:2380)
- [app/service/task/owner_fact_apply.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task/owner_fact_apply.py:1)
- [app/service/task_manager.py](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-binary-security/app/service/task_manager.py:1600)

## Current Static Verdict

### Already aligned

- task-type stage sequences
- archive-success barriers for upstream progression
- most owner-only stage start gating
- missing-entry-results failure escalation
- fake active-shell protection in finalize/snapshot logic
- normal-path reducer demotion

### Not fully aligned yet

- streaming seed helper ownership over first `stage_run` creation remains too implicit
- compat event paths still preserve old event-driven stage-run creation semantics
- repair/self-heal code is still too close to activation paths
- some failure bookkeeping still materializes stage runs in ways that can muddy timelines

## Async Vs Sync Boundary

Current static judgment against the target “sync where possible, async only where necessary” principle:

- keep synchronous in owner path:
  - stage start decision
  - stage terminal fact apply
  - downstream status fact apply
  - archive authoritative apply
  - streaming downstream item seed after authoritative upstream success
- keep asynchronous only where truly external or long-running:
  - child task execution
  - child task polling / external downstream fetch
  - archive copy / artifact IO
  - queue wakeup / retry / lease recovery
- legacy async compatibility that still exists but should keep shrinking:
  - state-event inbox record replay shell
  - retryable/dead-letter state-event repair
  - metrics snapshot publishing

This means the remaining refactor should not reintroduce reducer-style delayed business apply. The preferred direction is:

- owner runtime makes the decision
- owner runtime applies the authoritative fact inline when possible
- asynchronous records remain diagnostic/compatibility artifacts, not the main progression trigger

## Next Refactor Targets

Priority order:

1. Tighten `downstream.py` streaming seed helpers so stage-run creation only happens as part of first real item materialization by owner-authoritative paths.
2. Continue shrinking compatibility stage-run creation in `state_event_inbox.py` and residual compat apply paths.
3. Separate owner repair/self-heal signals from generic stage-start readiness calls.
4. Audit failure-projection-only `stage_run` creation for timeline purity.
5. Re-run full tests, then execute broad E2E and compare live timelines against this audit.

## Test Baseline

Verified on this audit pass:
- `PYTHONPATH=tests:. python -m unittest discover -q tests`
- Result: `Ran 962 tests ... OK`
