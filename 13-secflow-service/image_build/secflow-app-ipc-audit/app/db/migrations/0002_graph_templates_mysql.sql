CREATE TABLE IF NOT EXISTS ipc_audit_task_templates (
  template_id VARCHAR(64) PRIMARY KEY,
  workspace_id VARCHAR(128) NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT NULL,
  pipeline_mode VARCHAR(32) NOT NULL,
  executor_mode VARCHAR(32) NULL,
  model VARCHAR(255) NULL,
  provider_keys_json LONGTEXT NOT NULL,
  graph_source_json LONGTEXT NULL,
  report_outputs_json LONGTEXT NOT NULL,
  notes LONGTEXT NULL,
  created_by VARCHAR(128) NOT NULL,
  created_at VARCHAR(64) NOT NULL,
  updated_by VARCHAR(128) NULL,
  updated_at VARCHAR(64) NOT NULL,
  UNIQUE KEY uk_ipc_audit_task_templates_workspace_name (workspace_id, name),
  KEY idx_ipc_audit_task_templates_workspace_updated_at (workspace_id, updated_at)
);
