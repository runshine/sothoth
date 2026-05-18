CREATE TABLE IF NOT EXISTS ipc_audit_tasks (
  task_id VARCHAR(64) PRIMARY KEY,
  project_id VARCHAR(128) NULL,
  workspace_id VARCHAR(128) NOT NULL,
  title VARCHAR(255) NOT NULL,
  pipeline_mode VARCHAR(32) NOT NULL,
  input_kind VARCHAR(32) NOT NULL,
  project_path VARCHAR(512) NULL,
  report_path VARCHAR(512) NULL,
  status VARCHAR(32) NOT NULL,
  current_stage VARCHAR(128) NULL,
  latest_attempt_id VARCHAR(64) NULL,
  attempt_count INT NOT NULL DEFAULT 0,
  notes LONGTEXT NULL,
  idempotency_key VARCHAR(255) NULL,
  created_by VARCHAR(128) NOT NULL,
  created_at VARCHAR(64) NOT NULL,
  updated_at VARCHAR(64) NOT NULL,
  started_at VARCHAR(64) NULL,
  finished_at VARCHAR(64) NULL,
  message LONGTEXT NULL,
  active_target_ref VARCHAR(512)
    GENERATED ALWAYS AS (
      CASE
        WHEN status IN ('queued', 'running', 'cancel_requested') THEN COALESCE(project_path, report_path)
        ELSE NULL
      END
    ) STORED,
  UNIQUE KEY uk_ipc_audit_tasks_idempotency_key (idempotency_key),
  KEY idx_ipc_audit_tasks_project_created_at (project_id, created_at),
  KEY idx_ipc_audit_tasks_workspace_status (workspace_id, status),
  KEY idx_ipc_audit_tasks_workspace_path_status (workspace_id, project_path, status),
  UNIQUE KEY uk_ipc_audit_active_task_target (workspace_id, pipeline_mode, active_target_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ipc_audit_task_attempts (
  attempt_id VARCHAR(64) PRIMARY KEY,
  task_id VARCHAR(64) NOT NULL,
  attempt_no INT NOT NULL,
  status VARCHAR(32) NOT NULL,
  worker_id VARCHAR(128) NULL,
  lease_token VARCHAR(255) NULL,
  created_at VARCHAR(64) NOT NULL,
  updated_at VARCHAR(64) NOT NULL,
  claimed_at VARCHAR(64) NULL,
  heartbeat_at VARCHAR(64) NULL,
  lease_expires_at VARCHAR(64) NULL,
  started_at VARCHAR(64) NULL,
  finished_at VARCHAR(64) NULL,
  failure_reason LONGTEXT NULL,
  effective_config_json LONGTEXT NOT NULL,
  runtime_manifest_path VARCHAR(512) NULL,
  CONSTRAINT fk_ipc_audit_task_attempts_task
    FOREIGN KEY (task_id) REFERENCES ipc_audit_tasks(task_id) ON DELETE CASCADE,
  UNIQUE KEY uk_ipc_audit_attempts_task_attempt_no (task_id, attempt_no),
  KEY idx_ipc_audit_attempts_status (status),
  KEY idx_ipc_audit_attempts_task_status (task_id, status),
  KEY idx_ipc_audit_attempts_lease_expires_at (lease_expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ipc_audit_stage_runs (
  stage_run_id VARCHAR(96) PRIMARY KEY,
  attempt_id VARCHAR(64) NOT NULL,
  stage_name VARCHAR(128) NOT NULL,
  status VARCHAR(32) NOT NULL,
  attempt_no INT NOT NULL DEFAULT 1,
  return_code INT NULL,
  created_at VARCHAR(64) NOT NULL,
  updated_at VARCHAR(64) NOT NULL,
  started_at VARCHAR(64) NULL,
  finished_at VARCHAR(64) NULL,
  log_artifact_id VARCHAR(64) NULL,
  session_count INT NOT NULL DEFAULT 0,
  message LONGTEXT NULL,
  CONSTRAINT fk_ipc_audit_stage_runs_attempt
    FOREIGN KEY (attempt_id) REFERENCES ipc_audit_task_attempts(attempt_id) ON DELETE CASCADE,
  UNIQUE KEY uk_ipc_audit_stage_runs_attempt_stage (attempt_id, stage_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ipc_audit_task_events (
  event_seq BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  event_id VARCHAR(64) NOT NULL,
  task_id VARCHAR(64) NOT NULL,
  attempt_id VARCHAR(64) NULL,
  stage_name VARCHAR(128) NULL,
  event_type VARCHAR(128) NOT NULL,
  level VARCHAR(16) NOT NULL,
  message LONGTEXT NOT NULL,
  payload_json LONGTEXT NOT NULL,
  created_at VARCHAR(64) NOT NULL,
  CONSTRAINT fk_ipc_audit_task_events_task
    FOREIGN KEY (task_id) REFERENCES ipc_audit_tasks(task_id) ON DELETE CASCADE,
  CONSTRAINT fk_ipc_audit_task_events_attempt
    FOREIGN KEY (attempt_id) REFERENCES ipc_audit_task_attempts(attempt_id) ON DELETE CASCADE,
  UNIQUE KEY uk_ipc_audit_task_events_event_id (event_id),
  KEY idx_ipc_audit_events_task_seq (task_id, event_seq),
  KEY idx_ipc_audit_events_attempt_seq (attempt_id, event_seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ipc_audit_artifacts (
  artifact_id VARCHAR(64) PRIMARY KEY,
  task_id VARCHAR(64) NOT NULL,
  attempt_id VARCHAR(64) NOT NULL,
  stage_name VARCHAR(128) NULL,
  artifact_kind VARCHAR(64) NOT NULL,
  display_name VARCHAR(255) NOT NULL,
  relative_path VARCHAR(512) NOT NULL,
  content_type VARCHAR(128) NOT NULL,
  size BIGINT NOT NULL DEFAULT 0,
  sha256 VARCHAR(64) NULL,
  created_at VARCHAR(64) NOT NULL,
  CONSTRAINT fk_ipc_audit_artifacts_task
    FOREIGN KEY (task_id) REFERENCES ipc_audit_tasks(task_id) ON DELETE CASCADE,
  CONSTRAINT fk_ipc_audit_artifacts_attempt
    FOREIGN KEY (attempt_id) REFERENCES ipc_audit_task_attempts(attempt_id) ON DELETE CASCADE,
  UNIQUE KEY uk_ipc_audit_artifacts_attempt_path (attempt_id, relative_path),
  KEY idx_ipc_audit_artifacts_task_attempt (task_id, attempt_id),
  KEY idx_ipc_audit_artifacts_kind (artifact_kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ipc_audit_preset_projects (
  project_rowid BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  workspace_id VARCHAR(128) NOT NULL,
  project_key VARCHAR(255) NOT NULL,
  project_path VARCHAR(512) NOT NULL,
  display_name VARCHAR(512) NOT NULL,
  source VARCHAR(32) NOT NULL,
  has_idl TINYINT(1) NOT NULL DEFAULT 0,
  has_on_remote_request_cpp TINYINT(1) NOT NULL DEFAULT 0,
  has_existing_audit_report TINYINT(1) NOT NULL DEFAULT 0,
  has_existing_poc_report TINYINT(1) NOT NULL DEFAULT 0,
  last_scanned_at VARCHAR(64) NOT NULL,
  UNIQUE KEY uk_ipc_audit_preset_projects_workspace_key (workspace_id, project_key),
  UNIQUE KEY uk_ipc_audit_preset_projects_workspace_path (workspace_id, project_path),
  KEY idx_ipc_audit_preset_projects_workspace_source (workspace_id, source)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ipc_audit_catalog_refresh_jobs (
  refresh_job_id VARCHAR(64) PRIMARY KEY,
  workspace_id VARCHAR(128) NOT NULL,
  source VARCHAR(32) NOT NULL,
  status VARCHAR(32) NOT NULL,
  requested_by VARCHAR(128) NOT NULL,
  created_at VARCHAR(64) NOT NULL,
  started_at VARCHAR(64) NULL,
  finished_at VARCHAR(64) NULL,
  discovered_count INT NULL,
  error_message LONGTEXT NULL,
  active_refresh_marker TINYINT
    GENERATED ALWAYS AS (
      CASE
        WHEN status IN ('queued', 'running') THEN 1
        ELSE NULL
      END
    ) STORED,
  KEY idx_ipc_audit_catalog_refresh_jobs_workspace_created (workspace_id, created_at),
  KEY idx_ipc_audit_catalog_refresh_jobs_status (status),
  UNIQUE KEY uk_ipc_audit_active_catalog_refresh (workspace_id, source, active_refresh_marker)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ipc_audit_runtime_config (
  config_key VARCHAR(128) PRIMARY KEY,
  config_value_json LONGTEXT NOT NULL,
  updated_at VARCHAR(64) NOT NULL,
  updated_by VARCHAR(128) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
