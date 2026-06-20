# secflow-app-vuln-verify 本地版

这个目录现在是**本地单体开发版**：启动微服务不再依赖 Kubernetes、Auth 服务、Project 服务、ConfigCenter、Menu/Registry 服务，默认也不依赖远程 MySQL。

## 现在你本地可以这样跑（重点）

> 下面这组命令是本地验证最小闭环：默认使用容器内 SQLite，不需要 Auth / Project / ConfigCenter / Menu / Kubernetes，也不需要先安装 MySQL。你只需要提供一个 OpenAI-compatible 的 LLM API Key。

进入微服务目录：

```bash
cd /home/ubuntu/projects/SecAgentNet-v5/sothoth/13-secflow-service/image_build/secflow-app-vuln-verify
```

构建本地镜像：

```bash
docker build -t local/secflow-app-vuln-verify:local .
```

启动服务：

```bash
docker run --rm -p 8080:8080 \
  -e OPENAI_API_KEY="你的 key" \
  -e OPENAI_BASE_URL="https://api.openai.com/v1" \
  -e OPENAI_MODEL="gpt-4.1" \
  -v "$PWD/.local-data:/data" \
  local/secflow-app-vuln-verify:local
```

健康检查：

```bash
curl http://localhost:8080/api/app/vuln-verify/health
```

预期返回类似：

```json
{
  "status": "ok",
  "service": "secflow-app-vuln-verify",
  "service_id": "secflow-app-vuln-verify",
  "service_name": "漏洞验证服务",
  "build_version": null
}
```

如果你的 LLM 服务不是官方 OpenAI，只要兼容 OpenAI API，把 `OPENAI_BASE_URL` 换成你的网关地址，把 `OPENAI_MODEL` 换成对应模型名即可。

### 本地数据目录约定

上面的 `-v "$PWD/.local-data:/data"` 会把当前目录下的 `.local-data` 挂到容器 `/data`。例如项目 `demo` 的输入可以放在：

```text
.local-data/files/demo/reports
.local-data/files/demo/source
.local-data/files/demo/threat_model.md
```

容器内对应路径就是：

```text
/data/files/demo/reports
/data/files/demo/source
/data/files/demo/threat_model.md
```

服务输出和 SQLite 数据库也会持久化到 `.local-data` 下，删除容器不会丢。

## LLM 配置

服务会在启动时把环境变量写成 pi runtime 配置：

```text
/root/.pi/agent/models.json
/root/.pi/agent/settings.json
```

支持变量：

| 变量 | 说明 |
| --- | --- |
| `OPENAI_API_KEY` 或 `LLM_API_KEY` | LLM API Key |
| `OPENAI_BASE_URL` 或 `LLM_API_BASE` | OpenAI-compatible API Base URL |
| `OPENAI_MODEL` 或 `LLM_MODEL` | 默认模型 |
| `LLM_PROVIDER_KEY` | pi provider key，默认 `local_openai` |
| `LLM_PROVIDER_TYPE` | `openai` 或 `anthropic`，默认 `openai` |

没有配置 API Key 时，HTTP 服务仍会启动，但真正执行任务会失败并提示缺少 Key。

## 数据库

默认使用 SQLite：

```yaml
database:
  driver: sqlite
  sqlite_path: /data/vuln-verify/vuln_verify.db
```

如果你更想用本地 MySQL，可以运行容器时指定：

```bash
-e DATABASE_URL='mysql+pymysql://secflow:secflow@host.docker.internal:3306/secflow'
```

## 鉴权

默认关闭鉴权，所有项目 API 都可以直接访问。

如果想加一个本地共享 token：

```bash
-e SECFLOW_DEV_TOKEN='dev-token'
```

然后请求项目相关接口时带：

```bash
-H 'Authorization: Bearer dev-token'
```

## 创建任务

```bash
curl -X POST http://localhost:8080/api/app/vuln-verify/projects/demo/tasks \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "local verify",
    "reports_dir": "/data/files/demo/reports",
    "source_root": "/data/files/demo/source",
    "concurrency": 1
  }'
```

也可以直接提交 `raw_report`，服务会自动写到任务输入目录：

```json
{
  "name": "local verify",
  "raw_report": "# report\n**report_id**: r1\n...",
  "source_root": "/data/files/demo/source",
  "concurrency": 1
}
```

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
