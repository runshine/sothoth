create table if not exists ipc_audit_task_templates (
  template_id text primary key,
  workspace_id text not null,
  name text not null,
  description text,
  pipeline_mode text not null check (pipeline_mode in ('audit_then_poc', 'audit_only', 'poc_only', 'custom_graph')),
  executor_mode text check (executor_mode in ('mock', 'codex_cli', 'opencode_cli', 'agentflow_cli')),
  model text,
  provider_keys_json text not null default '[]',
  graph_source_json text,
  report_outputs_json text not null default '[]',
  notes text,
  created_by text not null,
  created_at text not null,
  updated_by text,
  updated_at text not null
);

create unique index if not exists uk_ipc_audit_task_templates_workspace_name
  on ipc_audit_task_templates(workspace_id, name);

create index if not exists idx_ipc_audit_task_templates_workspace_updated_at
  on ipc_audit_task_templates(workspace_id, updated_at desc);

pragma user_version = 3;
