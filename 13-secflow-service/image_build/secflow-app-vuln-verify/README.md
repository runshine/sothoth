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

服务启动和 Worker 执行任务前会通过机机 Token 调用 ConfigCenter：

```text
GET /api/configcenter/service/llm/providers
```

并将平台 LLM Provider 动态物化为 pi runtime 配置：

```text
$PI_CODING_AGENT_DIR/models.json
$PI_CODING_AGENT_DIR/settings.json
```

默认模型不在 vuln-verify 配置中写死；未在创建任务请求中显式传 `model` 时，服务不会传 `--model`，由 pi 根据 `settings.json` 中的 `defaultProvider` / `defaultModel` 使用 ConfigCenter 默认 Provider 的默认模型。容器 entrypoint 仍保留 `/data/pi-re-agent-config` 和 `/data/config` 的软链逻辑，作为 ConfigCenter 同步失败时的兼容兜底。
