# secflow-app-poc-gen-verify

A SecFlow microservice that wraps the `poc` CLI (`cli/poc_cli.py`, which itself
drives `claude -p` + gdb-via-tmux-mcp) to generate and GDB-verify PoCs from a
vulnerability report, entering via a given data-flow function. The bottom layer
is the **unchanged** CLI tool — the microservice just unpacks frontend JSON into
`poc` CLI args and runs it.

Architecture (Celery + Redis + MySQL, mirroring `secflow-app-dataflow-vuln-scan`):

```
frontend ─POST /tasks─▶ API (FastAPI/uvicorn) ─INSERT pending row─▶ MySQL
                                                                       ▲
                  scheduler pod (dispatcher: DB→Celery pump + stale scan) │ reads pending
                                                                       ▼
                                  Redis (broker) ──Celery message──▶ worker pod
                                  (result backend)                    │ run_poc_task(task_id)
                                                                      │   claim_specific_task (CAS)
                                                                      │   subprocess: poc -e … -r … -b … -o …
                                                                      │   commit_terminal_state_if_owner (CAS)
                                                                      ▼
                                                                   MySQL (status/artifacts)
```

Three roles, one image (role selected by k8s command/env):
- **API pod** — `python3 -m app.main` (uvicorn). `POC_ROLE=api`. DB init + menu registry via `runtime_bootstrap`. Does NOT run celery/dispatcher.
- **Worker pod** — `celery -A app.celery_app worker -P prefork -c 1 --queues=poc`. `POC_ROLE=worker`. Runs `@app.task run_poc_task` → `poc` CLI subprocess.
- **Scheduler pod** — `python -m app.dispatcher` + dedicated Redis StatefulSet. `POC_ROLE=scheduler`. DB→Celery pump + stale scan + startup reset.

DB is the source of truth; Redis is a transient queue (loss recovered by `_startup_reset`). `task_acks_late=True` + `task_reject_on_worker_lost=True` re-deliver on worker death; `claim_specific_task` prevents double-run; the stale scan re-queues orphans.

## API (FastAPI, port 8080, prefix `/api/app/poc-gen-verify`)

| method | path | purpose |
|---|---|---|
| POST   | `/tasks` | create a PoC task (INSERT pending; dispatcher publishes to Celery) → 201 |
| GET    | `/tasks` | list tasks (`?project_id=&page=&per_page=&status=`) |
| GET    | `/tasks/stats` | task counts by status (`?project_id=`) |
| GET    | `/tasks/{task_id}` | task detail (status, artifacts, returncode, …) |
| POST   | `/tasks/{task_id}/cancel` | revoke the Celery task (killpg poc+claude+gdb) + set cancelled |
| POST   | `/tasks/{task_id}/restart` | revoke + reset pending (epoch++/cv++) for re-run |
| GET    | `/tasks/{task_id}/logs` | raw `poc_cli.log` tail (`?tail=500`) |
| GET    | `/tasks/{task_id}/timeline` | high-level events (task_created/started/finished/cancelled/…) |
| GET    | `/tasks/{task_id}/artifacts` | list artifact filenames (DB + on-disk) |
| GET    | `/tasks/{task_id}/artifacts/{name}` | fetch an artifact's text content (e.g. `poc_report.md`) |
| GET    | `/health` | liveness |
| GET    | `/ready`  | readiness — DB + `claude`/`tmux`/`gdb`/`tmux-mcp`/`poc` on PATH |

### Request body (`POST /tasks`)
```json
{
  "project_id": "proj-001",
  "task_name": "IPSEC_SOCKI_PipeMsg PoC",
  "entry_function": "IPSEC_SOCKI_PipeMsg",
  "vuln_report_path": "/workspace/reports/result_001.md",
  "binary_dir": "/workspace/firmware",
  "output_dir": "/workspace/out/vuln-001",
  "model": "glm-5.2",
  "effort": "xhigh",
  "session_name": "vuln001-task",
  "session_dir": "/workspace/sessions/vuln001",
  "timeout": 7200
}
```
Mapped to: `poc -e <entry_function> -r <vuln_report_path> -b <binary_dir> -o <output_dir> --timeout <timeout> [--model --effort --session-name --session-id --session-dir]`. Only `project_id`/`entry_function`/`vuln_report_path`/`binary_dir` are required.

`status`: `pending|running|succeeded|failed|timeout|cancelled`.

## Pod dependencies (baked in the image)

The Dockerfile (node 22 multi-stage → python 3.11) installs everything the `poc` CLI needs:

| dep | how |
|---|---|
| **claude-code** | `npm install -g @anthropic-ai/claude-code` (node 22 via multi-stage) |
| **tmux-mcp** | `npm install -g tmux-mcp` (registered in `.claude.json`) |
| **tmux** / **gdb** | `apt-get install tmux gdb` (+ Pod `SYS_PTRACE`) |
| **C toolchain** | `build-essential gcc g++ make binutils libc-dev` (PoC harness compiles C) |
| **python 3.11** | base image (+ fastapi/uvicorn/sqlalchemy/celery/redis from `requirements.txt`) |
| **the `poc` CLI** | `cli/poc_cli.py` + `cli/poc` → `/usr/local/bin/` |

`entrypoint.sh` installs `~/.claude.json` + `~/.claude/settings.json` templates on first start, resolves the `tmux-mcp` path, marks onboarding done, then `exec "$@"`. It runs for **all** roles (the worker needs it — `poc` spawns `claude`). `ANTHROPIC_AUTH_TOKEN` (GLM/dashscope bearer) is **not** baked; it comes from the k8s `Secret` / `.env`.

## Local dev / testing (docker compose)

```bash
cp .env.example .env  # set ANTHROPIC_AUTH_TOKEN (worker needs it for claude)
./scripts/dev.sh      # builds the image once + brings up redis/mysql/api/worker/scheduler
# or manually: docker compose up --build
curl http://127.0.0.1:8080/api/app/poc-gen-verify/health
curl http://127.0.0.1:8080/api/app/poc-gen-verify/ready
```
The `poc` CLI is unchanged and still runs standalone: `cli/poc --dry-run -e fn -r report.md -b /workspace/firmware`.

## Deploy (k8s)

```bash
# 1. build + push (mirror the platform's buildx workflow)
docker build -t ghcr.io/runshine/secflow-app-poc-gen-verify:latest .

# 2. create the secret with the GLM token
kubectl create secret generic secflow-app-poc-gen-verify-secret \
  --from-literal=ANTHROPIC_AUTH_TOKEN='sk-ws-...' -n secflow-ns

# 3. apply (redis + scheduler + api + worker + service + configmap + pvc)
kubectl apply -f k8s-pvc.yaml \
  -f k8s-redis-service.yaml -f k8s-redis-statefulset.yaml \
  -f k8s-configmap.yaml \
  -f k8s-scheduler-deployment.yaml \
  -f k8s-api-deployment.yaml -f k8s-service.yaml \
  -f k8s-worker-deployment.yaml
```
- Namespace `secflow-ns`. API 2 replicas; worker 2 replicas (RollingUpdate, 1 down at a time); scheduler 1 replica; Redis 1 replica (StatefulSet, 10Gi `local-path`).
- PVC mounted at `/var/lib/secflow-poc-gen-verify` (state/logs) + `/workspace` (firmware I/O) for api+worker.
- Probes: api `/ready`+`/health` on 8080; worker/scheduler `pgrep` exec liveness.
- `SYS_PTRACE` for gdb (api + worker).
- DB = shared platform MySQL (`mysql.sothothv2-ns.svc.cluster.local`, db `secflow`); tables `secflow_app_poc_tasks` + `secflow_app_poc_task_events` auto-created on first init.

## Files
```
app/                    FastAPI + Celery service
  main.py               FastAPI factory + lifespan (runtime_bootstrap)
  routes.py             REST endpoints (tasks CRUD + cancel/restart/logs/timeline/artifacts)
  api_schemas.py        Pydantic request/response models
  config.py             Settings (env) + service.yaml loader (DB + registry)
  runtime_context.py    role + lease/heartbeat config (POC_* env)
  time_utils.py         UTC+8 helpers
  celery_app.py         Celery instance + config (broker/backend = Redis)
  celery_tasks.py       @app.task run_poc_task + task_revoked killpg
  dispatcher.py         scheduler sidecar: DB→Celery pump + stale scan + startup reset
  runner.py             `poc` CLI invocation (build_poc_cmd + run_poc_cli subprocess)
  db/
    __init__.py         engine, SessionLocal, get_db, init_db, ensure_db, migrations
    models.py           AppPocTask + AppPocTaskEvent ORM
  service/
    task_service.py     task lifecycle + _execute_task (subprocess + CAS commit)
    execution_coordinator.py  claim/begin/commit/renew/still_owner CAS primitives
    runtime_bootstrap.py  API pod DB init + menu registry
    registry_service.py   menu-service HTTP heartbeat
cli/                    the `poc` CLI — CANONICAL source of truth (UNCHANGED)
service.yaml            k8s/prod config (DB = platform MySQL, menu registration)
service.dev.yaml        docker-compose override (DB = `mysql` service, no registry)
docker-compose.yml      local dev stack (redis + mysql + api + worker + scheduler)
Dockerfile / entrypoint.sh / .claude.json / settings.json  image + claude config
k8s-*.yaml              api/worker/scheduler deployments + redis + service + configmap + pvc + secret.example
requirements.txt
```

## notes
- image pre-installs `file` + `xxd` (per session analysis of the completed IPSEC task — the agent hit "command not found" for both).

## 漏洞判定引擎契约接入（Contract v2.3）

本服务已按《漏洞判定引擎接入手册》（Contract v2.3）改造为平台可调度的漏洞判定引擎：
收到平台 intake 请求后生成 PoC 并在 GDB 下触发验证，把「是不是漏洞」的结论推回平台。

### 角色映射
PoC 验证结果 → 契约结论：

| 内部状态 | poc_path | 契约状态 | 契约结果 | 说明 |
|---|---|---|---|---|
| `pending` | — | 等待中 | null | 已入队 |
| `running` | — | 进行中 | null | poc CLI 执行中 |
| `succeeded` | `a` | 已完成 | 是 | GDB 成功触发（漏洞确认）|
| `succeeded` | `b` | 已完成 | 不是 | 证伪/不可达（误报）|
| `succeeded` | None | 已完成 | 不可证 | 未达 Stage2 |
| `failed`/`timeout`/`cancelled` | — | 失败 | null | 引擎内部无法得出结论 |

路径A（GDB 触发崩溃 = 内存安全类）默认携带 `confirmed_category=内存安全类型`，推送前经接口6目录校验存在才填。

### 六个接口实现

**平台调用本服务（接口1/2/5，挂载在 `EngineConfig.endpoint_prefix`=`/api/app/poc-gen-verify/intake`）：**

| # | 方法+路径 | 用途 |
|---|---|---|
| 1 | `POST /api/app/poc-gen-verify/intake` | 接收漏洞确认请求（intake submission + `vuln_id`）；同步返「等待中」|
| 2 | `POST /api/app/poc-gen-verify/intake/results/batch` | 批量结果查询（兖底）|
| 5 | `POST /api/app/poc-gen-verify/intake/results/confirmed` | 按北京时间窗口查询已确认漏洞（对账）|

**本服务调用平台（接口3/4/6，由 `app/engine_heartbeat.py` / `app/results_push.py` / `app/category_catalog.py` 实现）：**

| # | 接口 | 用途 | 触发点 |
|---|---|---|---|
| 3 | `POST /api/vuln/internal/vuln-confirm/engines/heartbeat` | 心跳保活 | API pod 启动后立即首次，30s 周期（线程）|
| 4 | `POST /api/vuln/internal/vuln-confirm/results/push` | 主动推送结果 | worker claim 后推「进行中」；终态提交后推终态 |
| 6 | `GET /api/vuln/vuln-categories` | 漏洞分类目录 | 启动/缓存失效时拉取（验证 `confirmed_category`）|

### 关键设计

- **PUSH 为主、PULL 兑底**：worker 完成后立即接口4推送终态（秒级）；平台接口2每 60s 兖底拉取丢失的 case。
- **幂等**：接口1 同 `vuln_id` 重试不重复创建任务（已存在则返「等待中」）。
- **同步响应永不返终态**：接口1 统一返「等待中」/「进行中」，终态只走接口4/接口2。
- **中文键严格匹配**：`漏洞ID`/`推理引擎.{引擎名称,引擎版本}`/`状态`/`结果`/`理由`/`confirmed_category`。
- **新数据列**：`secflow_app_poc_tasks.vuln_id`（NULL=前端任务；非 NULL=契约任务，自动迁移）。
- **不破坏现有链路**：前端 `POST /tasks` 与 poc CLI 子进程调用链不变；契约任务是同一条 pending→Celery→worker 管道。

### 部署注意
- 平台管理员需在漏洞中心后台预注册引擎：`engine_name=secflow-app-poc-gen-verify`、`endpoint=<ingress>/api/app/poc-gen-verify/intake`、`bind_tools=<产出二进制漏洞的工具 toolid>`。
- `subject.source_root` 须指向漏洞/固件根目录（映射为 `poc -b binary_dir`）。
- 引擎配置可通过 service.yaml `engine` 段或环境变量覆盖（`SECFLOW_ENGINE_NAME` / `SECFLOW_VULN_CONFIRM_HEARTBEAT_URL` / `SECFLOW_ENGINE_RESULTS_PUSH_URL` / `SECFLOW_ENGINE_VULN_CATEGORIES_URL` 等）。

### 相关文件
```
app/contract.py             契约适配层（接口1/2/5 路由 + 状态映射 + 中文 schema）
app/results_push.py         接口4 主动推送 + build_push_payload
app/engine_heartbeat.py     接口3 心跳线程（threading + time.sleep，遵循项目规则）
app/category_catalog.py     接口6 分类目录客户端（缓存 + 兜底默认）
app/config.py               EngineConfig + get_engine_config()（service.yaml + env 覆盖）
app/db/models.py            AppPocTask.vuln_id 新列
app/db/__init__.py           vuln_id 列 + 索引迁移
app/service/task_service.py create_contract_task + 推送集成（running/terminal）
app/service/runtime_bootstrap.py  启动/停止引擎心跳
app/main.py                 挂载契约路由
```
