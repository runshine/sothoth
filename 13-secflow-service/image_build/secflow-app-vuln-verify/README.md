# secflow-app-vuln-verify

SecFlow 漏洞验证服务，MVP 封装 `vuln-verify` CLI 为项目隔离的 HTTP Task API。

## API

```text
GET  /api/app/vuln-verify/health
GET  /api/app/vuln-verify/ready
GET  /api/app/vuln-verify/projects/{project_id}/tasks
POST /api/app/vuln-verify/projects/{project_id}/tasks
GET  /api/app/vuln-verify/projects/{project_id}/tasks/{task_id}
POST /api/app/vuln-verify/projects/{project_id}/tasks/{task_id}/terminate
POST /api/app/vuln-verify/projects/{project_id}/tasks/{task_id}/rerun
GET  /api/app/vuln-verify/projects/{project_id}/tasks/{task_id}/result
GET  /api/app/vuln-verify/projects/{project_id}/tasks/{task_id}/artifacts
GET  /api/app/vuln-verify/projects/{project_id}/tasks/{task_id}/artifacts/content?path=...
```

## 创建任务

```json
{
  "name": "漏洞验证",
  "reports_dir": "/data/files/<project>/reports",
  "source_root": "/data/files/<project>/source",
  "binary_root": "/data/files/<project>/binary",
  "threat_path": "/data/files/<project>/threat_model.md",
  "model": "share_codex/gpt-5.4",
  "concurrency": 4,
  "resume": false
}
```

输出目录自动生成：

```text
/data/files/{project_id}/app/secflow-app-vuln-verify/{task_id}/output
```

## LLM Provider

参考 dataflow-vuln-scan：容器启动时把 `/data/config/models.json` 软链到 `$PI_CODING_AGENT_DIR/models.json`，不从 ConfigCenter 动态物化。
