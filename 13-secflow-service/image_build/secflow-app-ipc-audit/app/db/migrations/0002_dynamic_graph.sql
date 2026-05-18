PRAGMA foreign_keys = OFF;
BEGIN TRANSACTION;

ALTER TABLE ipc_audit_tasks RENAME TO ipc_audit_tasks_old;
ALTER TABLE ipc_audit_task_attempts RENAME TO ipc_audit_task_attempts_old;
ALTER TABLE ipc_audit_stage_runs RENAME TO ipc_audit_stage_runs_old;
ALTER TABLE ipc_audit_task_events RENAME TO ipc_audit_task_events_old;
ALTER TABLE ipc_audit_artifacts RENAME TO ipc_audit_artifacts_old;

DROP INDEX IF EXISTS uk_ipc_audit_tasks_idempotency_key;
DROP INDEX IF EXISTS idx_ipc_audit_tasks_project_created_at;
DROP INDEX IF EXISTS idx_ipc_audit_tasks_workspace_status;
DROP INDEX IF EXISTS idx_ipc_audit_tasks_workspace_path_status;
DROP INDEX IF EXISTS uk_ipc_audit_active_task_target;
DROP INDEX IF EXISTS uk_ipc_audit_attempts_task_attempt_no;
DROP INDEX IF EXISTS idx_ipc_audit_attempts_status;
DROP INDEX IF EXISTS idx_ipc_audit_attempts_task_status;
DROP INDEX IF EXISTS idx_ipc_audit_attempts_lease_expires_at;
DROP INDEX IF EXISTS uk_ipc_audit_stage_runs_attempt_stage;
DROP INDEX IF EXISTS idx_ipc_audit_events_task_seq;
DROP INDEX IF EXISTS idx_ipc_audit_events_attempt_seq;
DROP INDEX IF EXISTS uk_ipc_audit_artifacts_attempt_path;
DROP INDEX IF EXISTS idx_ipc_audit_artifacts_task_attempt;
DROP INDEX IF EXISTS idx_ipc_audit_artifacts_kind;

create table ipc_audit_tasks (
  task_id text primary key,
  project_id text,
  workspace_id text not null,
  title text not null,
  pipeline_mode text not null check (pipeline_mode in ('audit_then_poc', 'audit_only', 'poc_only', 'custom_graph')),
  input_kind text not null check (input_kind in ('preset_project', 'custom_project', 'existing_audit_report')),
  project_path text,
  report_path text,
  status text not null check (status in (
    'queued', 'running', 'succeeded', 'partial_success', 'failed',
    'cancel_requested', 'cancelled', 'needs_attention'
  )),
  current_stage text,
  latest_attempt_id text,
  attempt_count integer not null default 0 check (attempt_count >= 0),
  notes text,
  idempotency_key text,
  created_by text not null,
  created_at text not null,
  updated_at text not null,
  started_at text,
  finished_at text,
  message text,
  check (
    (input_kind in ('preset_project', 'custom_project') and project_path is not null and report_path is null)
    or
    (input_kind = 'existing_audit_report' and report_path is not null)
  )
);

create unique index uk_ipc_audit_tasks_idempotency_key
  on ipc_audit_tasks(idempotency_key)
  where idempotency_key is not null;
create index idx_ipc_audit_tasks_project_created_at
  on ipc_audit_tasks(project_id, created_at desc);
create index idx_ipc_audit_tasks_workspace_status
  on ipc_audit_tasks(workspace_id, status);
create index idx_ipc_audit_tasks_workspace_path_status
  on ipc_audit_tasks(workspace_id, project_path, status);
create unique index uk_ipc_audit_active_task_target
  on ipc_audit_tasks(workspace_id, pipeline_mode, ifnull(project_path, report_path))
  where status in ('queued', 'running', 'cancel_requested');

insert into ipc_audit_tasks (
  task_id, project_id, workspace_id, title, pipeline_mode, input_kind, project_path, report_path,
  status, current_stage, latest_attempt_id, attempt_count, notes, idempotency_key, created_by,
  created_at, updated_at, started_at, finished_at, message
)
select
  task_id, project_id, workspace_id, title, pipeline_mode, input_kind, project_path, report_path,
  status, current_stage, latest_attempt_id, attempt_count, notes, idempotency_key, created_by,
  created_at, updated_at, started_at, finished_at, message
from ipc_audit_tasks_old;

create table ipc_audit_task_attempts (
  attempt_id text primary key,
  task_id text not null,
  attempt_no integer not null check (attempt_no >= 1),
  status text not null check (status in (
    'queued', 'claimed', 'running', 'succeeded', 'partial_success', 'failed',
    'cancel_requested', 'cancelled', 'timed_out', 'lost'
  )),
  worker_id text,
  lease_token text,
  created_at text not null,
  updated_at text not null,
  claimed_at text,
  heartbeat_at text,
  lease_expires_at text,
  started_at text,
  finished_at text,
  failure_reason text,
  effective_config_json text not null default '{}',
  runtime_manifest_path text,
  foreign key (task_id) references ipc_audit_tasks(task_id) on delete cascade
);

create unique index uk_ipc_audit_attempts_task_attempt_no
  on ipc_audit_task_attempts(task_id, attempt_no);
create index idx_ipc_audit_attempts_status
  on ipc_audit_task_attempts(status);
create index idx_ipc_audit_attempts_task_status
  on ipc_audit_task_attempts(task_id, status);
create index idx_ipc_audit_attempts_lease_expires_at
  on ipc_audit_task_attempts(lease_expires_at);

insert into ipc_audit_task_attempts (
  attempt_id, task_id, attempt_no, status, worker_id, lease_token, created_at, updated_at,
  claimed_at, heartbeat_at, lease_expires_at, started_at, finished_at, failure_reason,
  effective_config_json, runtime_manifest_path
)
select
  attempt_id, task_id, attempt_no, status, worker_id, lease_token, created_at, updated_at,
  claimed_at, heartbeat_at, lease_expires_at, started_at, finished_at, failure_reason,
  effective_config_json, runtime_manifest_path
from ipc_audit_task_attempts_old;

create table ipc_audit_stage_runs (
  stage_run_id text primary key,
  attempt_id text not null,
  stage_name text not null,
  status text not null check (status in (
    'pending', 'queued', 'running', 'succeeded', 'failed',
    'skipped', 'cancelled', 'timed_out'
  )),
  attempt_no integer not null default 1 check (attempt_no >= 1),
  return_code integer,
  created_at text not null,
  updated_at text not null,
  started_at text,
  finished_at text,
  log_artifact_id text,
  session_count integer not null default 0 check (session_count >= 0),
  message text,
  foreign key (attempt_id) references ipc_audit_task_attempts(attempt_id) on delete cascade
);

create unique index uk_ipc_audit_stage_runs_attempt_stage
  on ipc_audit_stage_runs(attempt_id, stage_name);

insert into ipc_audit_stage_runs (
  stage_run_id, attempt_id, stage_name, status, attempt_no, return_code, created_at,
  updated_at, started_at, finished_at, log_artifact_id, session_count, message
)
select
  stage_run_id, attempt_id, stage_name, status, attempt_no, return_code, created_at,
  updated_at, started_at, finished_at, log_artifact_id, session_count, message
from ipc_audit_stage_runs_old;

create table ipc_audit_task_events (
  event_seq integer primary key autoincrement,
  event_id text not null unique,
  task_id text not null,
  attempt_id text,
  stage_name text,
  event_type text not null,
  level text not null check (level in ('debug', 'info', 'warning', 'error')),
  message text not null,
  payload_json text not null default '{}',
  created_at text not null,
  foreign key (task_id) references ipc_audit_tasks(task_id) on delete cascade,
  foreign key (attempt_id) references ipc_audit_task_attempts(attempt_id) on delete cascade
);

create index idx_ipc_audit_events_task_seq
  on ipc_audit_task_events(task_id, event_seq);
create index idx_ipc_audit_events_attempt_seq
  on ipc_audit_task_events(attempt_id, event_seq);

insert into ipc_audit_task_events (
  event_seq, event_id, task_id, attempt_id, stage_name, event_type, level, message, payload_json, created_at
)
select
  event_seq, event_id, task_id, attempt_id, stage_name, event_type, level, message, payload_json, created_at
from ipc_audit_task_events_old;

create table ipc_audit_artifacts (
  artifact_id text primary key,
  task_id text not null,
  attempt_id text not null,
  stage_name text,
  artifact_kind text not null check (artifact_kind in (
    'audit_report', 'audit_log', 'poc_report', 'poc_log',
    'audited_result_json', 'entries_snapshot', 'runtime_manifest', 'session_file',
    'stage_log', 'report_output', 'graph_manifest'
  )),
  display_name text not null,
  relative_path text not null,
  content_type text not null,
  size integer not null default 0 check (size >= 0),
  sha256 text,
  created_at text not null,
  foreign key (task_id) references ipc_audit_tasks(task_id) on delete cascade,
  foreign key (attempt_id) references ipc_audit_task_attempts(attempt_id) on delete cascade
);

create unique index uk_ipc_audit_artifacts_attempt_path
  on ipc_audit_artifacts(attempt_id, relative_path);
create index idx_ipc_audit_artifacts_task_attempt
  on ipc_audit_artifacts(task_id, attempt_id);
create index idx_ipc_audit_artifacts_kind
  on ipc_audit_artifacts(artifact_kind);

insert into ipc_audit_artifacts (
  artifact_id, task_id, attempt_id, stage_name, artifact_kind, display_name,
  relative_path, content_type, size, sha256, created_at
)
select
  artifact_id, task_id, attempt_id, stage_name, artifact_kind, display_name,
  relative_path, content_type, size, sha256, created_at
from ipc_audit_artifacts_old;

DROP TABLE ipc_audit_tasks_old;
DROP TABLE ipc_audit_task_attempts_old;
DROP TABLE ipc_audit_stage_runs_old;
DROP TABLE ipc_audit_task_events_old;
DROP TABLE ipc_audit_artifacts_old;

COMMIT;
PRAGMA foreign_keys = ON;
PRAGMA user_version = 2;
