PRAGMA user_version = 1;

create table if not exists kernel_scan_tasks (
  task_id text primary key,
  title text not null,
  pipeline_mode text not null check (pipeline_mode in ('entry_only', 'audit_only', 'poc_only', 'entry_audit_poc')),
  kernel_dir text not null,
  devlist_json text,
  status text not null check (status in (
    'queued', 'running', 'succeeded', 'partial_success', 'failed',
    'cancel_requested', 'cancelled'
  )),
  current_stage text check (current_stage is null or current_stage in ('entry', 'audit', 'poc')),
  latest_attempt_id text,
  attempt_count integer not null default 0 check (attempt_count >= 0),
  notes text,
  created_by text not null,
  created_at text not null,
  updated_at text not null,
  started_at text,
  finished_at text,
  message text
);

create index if not exists idx_kernel_scan_tasks_status
  on kernel_scan_tasks(status);

create table if not exists kernel_scan_attempts (
  attempt_id text primary key,
  task_id text not null,
  attempt_no integer not null check (attempt_no >= 1),
  status text not null check (status in (
    'queued', 'claimed', 'running', 'succeeded', 'partial_success', 'failed',
    'cancel_requested', 'cancelled', 'timed_out', 'lost'
  )),
  worker_id text,
  created_at text not null,
  updated_at text not null,
  claimed_at text,
  heartbeat_at text,
  lease_expires_at text,
  started_at text,
  finished_at text,
  failure_reason text,
  effective_config_json text not null default '{}',
  foreign key (task_id) references kernel_scan_tasks(task_id) on delete cascade
);

create unique index if not exists uk_kernel_scan_attempts_task_no
  on kernel_scan_attempts(task_id, attempt_no);

create index if not exists idx_kernel_scan_attempts_status
  on kernel_scan_attempts(status);

create index if not exists idx_kernel_scan_attempts_lease
  on kernel_scan_attempts(lease_expires_at);

create table if not exists kernel_scan_stage_runs (
  stage_run_id text primary key,
  attempt_id text not null,
  stage_name text not null check (stage_name in ('entry', 'audit', 'poc')),
  status text not null check (status in (
    'pending', 'running', 'succeeded', 'failed',
    'skipped', 'cancelled', 'timed_out'
  )),
  return_code integer,
  created_at text not null,
  updated_at text not null,
  started_at text,
  finished_at text,
  log_artifact_id text,
  message text,
  metadata_json text not null default '{}',
  foreign key (attempt_id) references kernel_scan_attempts(attempt_id) on delete cascade
);

create unique index if not exists uk_kernel_scan_stage_runs_attempt_stage
  on kernel_scan_stage_runs(attempt_id, stage_name);

create table if not exists kernel_scan_events (
  event_seq integer primary key autoincrement,
  event_id text not null unique,
  task_id text not null,
  attempt_id text,
  stage_name text check (stage_name is null or stage_name in ('entry', 'audit', 'poc')),
  event_type text not null,
  level text not null check (level in ('debug', 'info', 'warning', 'error')),
  message text not null,
  payload_json text not null default '{}',
  created_at text not null,
  foreign key (task_id) references kernel_scan_tasks(task_id) on delete cascade
);

create index if not exists idx_kernel_scan_events_task_seq
  on kernel_scan_events(task_id, event_seq);

create table if not exists kernel_scan_artifacts (
  artifact_id text primary key,
  task_id text not null,
  attempt_id text not null,
  stage_name text check (stage_name is null or stage_name in ('entry', 'audit', 'poc')),
  artifact_kind text not null check (artifact_kind in (
    'entry_results', 'entry_log',
    'audit_report', 'audit_log',
    'poc_results', 'poc_log', 'poc_detail',
    'runtime_manifest'
  )),
  display_name text not null,
  relative_path text not null,
  content_type text not null,
  size integer not null default 0 check (size >= 0),
  created_at text not null,
  foreign key (task_id) references kernel_scan_tasks(task_id) on delete cascade,
  foreign key (attempt_id) references kernel_scan_attempts(attempt_id) on delete cascade
);

create index if not exists idx_kernel_scan_artifacts_task_attempt
  on kernel_scan_artifacts(task_id, attempt_id);
