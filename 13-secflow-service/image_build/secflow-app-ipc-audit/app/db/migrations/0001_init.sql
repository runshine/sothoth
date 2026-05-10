PRAGMA user_version = 1;

create table if not exists ipc_audit_tasks (
  task_id text primary key,
  project_id text,
  workspace_id text not null,
  title text not null,
  pipeline_mode text not null check (pipeline_mode in ('audit_then_poc', 'audit_only', 'poc_only')),
  input_kind text not null check (input_kind in ('preset_project', 'custom_project', 'existing_audit_report')),
  project_path text,
  report_path text,
  status text not null check (status in (
    'queued', 'running', 'succeeded', 'partial_success', 'failed',
    'cancel_requested', 'cancelled', 'needs_attention'
  )),
  current_stage text check (current_stage is null or current_stage in ('audit', 'poc')),
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

create unique index if not exists uk_ipc_audit_tasks_idempotency_key
  on ipc_audit_tasks(idempotency_key)
  where idempotency_key is not null;

create index if not exists idx_ipc_audit_tasks_project_created_at
  on ipc_audit_tasks(project_id, created_at desc);

create index if not exists idx_ipc_audit_tasks_workspace_status
  on ipc_audit_tasks(workspace_id, status);

create index if not exists idx_ipc_audit_tasks_workspace_path_status
  on ipc_audit_tasks(workspace_id, project_path, status);

create unique index if not exists uk_ipc_audit_active_task_target
  on ipc_audit_tasks(workspace_id, pipeline_mode, ifnull(project_path, report_path))
  where status in ('queued', 'running', 'cancel_requested');

create table if not exists ipc_audit_task_attempts (
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

create unique index if not exists uk_ipc_audit_attempts_task_attempt_no
  on ipc_audit_task_attempts(task_id, attempt_no);

create index if not exists idx_ipc_audit_attempts_status
  on ipc_audit_task_attempts(status);

create index if not exists idx_ipc_audit_attempts_task_status
  on ipc_audit_task_attempts(task_id, status);

create index if not exists idx_ipc_audit_attempts_lease_expires_at
  on ipc_audit_task_attempts(lease_expires_at);

create table if not exists ipc_audit_stage_runs (
  stage_run_id text primary key,
  attempt_id text not null,
  stage_name text not null check (stage_name in ('audit', 'poc')),
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

create unique index if not exists uk_ipc_audit_stage_runs_attempt_stage
  on ipc_audit_stage_runs(attempt_id, stage_name);

create table if not exists ipc_audit_task_events (
  event_seq integer primary key autoincrement,
  event_id text not null unique,
  task_id text not null,
  attempt_id text,
  stage_name text check (stage_name is null or stage_name in ('audit', 'poc')),
  event_type text not null,
  level text not null check (level in ('debug', 'info', 'warning', 'error')),
  message text not null,
  payload_json text not null default '{}',
  created_at text not null,
  foreign key (task_id) references ipc_audit_tasks(task_id) on delete cascade,
  foreign key (attempt_id) references ipc_audit_task_attempts(attempt_id) on delete cascade
);

create index if not exists idx_ipc_audit_events_task_seq
  on ipc_audit_task_events(task_id, event_seq);

create index if not exists idx_ipc_audit_events_attempt_seq
  on ipc_audit_task_events(attempt_id, event_seq);

create table if not exists ipc_audit_artifacts (
  artifact_id text primary key,
  task_id text not null,
  attempt_id text not null,
  stage_name text check (stage_name is null or stage_name in ('audit', 'poc')),
  artifact_kind text not null check (artifact_kind in (
    'audit_report', 'audit_log', 'poc_report', 'poc_log',
    'audited_result_json', 'entries_snapshot', 'runtime_manifest', 'session_file'
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

create unique index if not exists uk_ipc_audit_artifacts_attempt_path
  on ipc_audit_artifacts(attempt_id, relative_path);

create index if not exists idx_ipc_audit_artifacts_task_attempt
  on ipc_audit_artifacts(task_id, attempt_id);

create index if not exists idx_ipc_audit_artifacts_kind
  on ipc_audit_artifacts(artifact_kind);

create table if not exists ipc_audit_preset_projects (
  project_rowid integer primary key autoincrement,
  workspace_id text not null,
  project_key text not null,
  project_path text not null,
  display_name text not null,
  source text not null check (source in ('entries_file', 'bundle_scan')),
  has_idl integer not null default 0 check (has_idl in (0, 1)),
  has_on_remote_request_cpp integer not null default 0 check (has_on_remote_request_cpp in (0, 1)),
  has_existing_audit_report integer not null default 0 check (has_existing_audit_report in (0, 1)),
  has_existing_poc_report integer not null default 0 check (has_existing_poc_report in (0, 1)),
  last_scanned_at text not null
);

create unique index if not exists uk_ipc_audit_preset_projects_workspace_key
  on ipc_audit_preset_projects(workspace_id, project_key);

create unique index if not exists uk_ipc_audit_preset_projects_workspace_path
  on ipc_audit_preset_projects(workspace_id, project_path);

create index if not exists idx_ipc_audit_preset_projects_workspace_source
  on ipc_audit_preset_projects(workspace_id, source);

create table if not exists ipc_audit_catalog_refresh_jobs (
  refresh_job_id text primary key,
  workspace_id text not null,
  source text not null check (source in ('entries_file', 'bundle_scan')),
  status text not null check (status in ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  requested_by text not null,
  created_at text not null,
  started_at text,
  finished_at text,
  discovered_count integer,
  error_message text
);

create index if not exists idx_ipc_audit_catalog_refresh_jobs_workspace_created
  on ipc_audit_catalog_refresh_jobs(workspace_id, created_at desc);

create index if not exists idx_ipc_audit_catalog_refresh_jobs_status
  on ipc_audit_catalog_refresh_jobs(status);

create unique index if not exists uk_ipc_audit_active_catalog_refresh
  on ipc_audit_catalog_refresh_jobs(workspace_id, source)
  where status in ('queued', 'running');

create table if not exists ipc_audit_runtime_config (
  config_key text primary key,
  config_value_json text not null,
  updated_at text not null,
  updated_by text not null
);
