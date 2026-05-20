# SecFlow Kernel Scan Service API

Base URL: `/api/app/kernel-scan`

## 服务地址

| 部署形态 | Host | Port | 完整示例 |
|---------|------|------|----------|
| 容器内监听 | `0.0.0.0` | `8080` | `http://127.0.0.1:8080/api/app/kernel-scan/health`（容器内 / healthcheck） |
| docker-compose 默认 | 宿主机 IP | `18081`（可由 `KERNEL_SCAN_PORT` 覆盖） | `http://<host>:18081/api/app/kernel-scan/health` |
| 当前部署机（参考） | `172.31.30.81` | `18081` | `http://172.31.30.81:18081/api/app/kernel-scan/health` |

宿主机端口由 docker-compose 的 `ports: "${KERNEL_SCAN_PORT:-18081}:8080"` 决定；容器内端口和监听地址由环境变量 `KERNEL_SCAN_HOST` / `KERNEL_SCAN_PORT` 控制（容器内默认 `0.0.0.0:8080`）。下文所有路径均以 Base URL `/api/app/kernel-scan` 为前缀。

## Health

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | 健康检查 |
| GET | /ready | 就绪检查（数据库可用） |

## Devices

### POST /devices/adb/connect — 连接远程 ADB 设备

接口不再接收 IP 参数，前端发空请求即可。后端固定使用 `172.31.30.81:15037`，在容器服务进程内设置 `ADB_SERVER_SOCKET=tcp:172.31.30.81:15037`。接口执行 `adb devices`，并在发现 `device` 状态设备且 `adb -s <serial> shell true` 成功后，才把同一个 `export ADB_SERVER_SOCKET=...` 写入 `~/.bashrc`。接口响应只返回 `adb devices` 命令结果。

**Request Body:**

```json
{}
```

**Response (200):**

```json
{
  "command": ["ADB_SERVER_SOCKET=tcp:172.31.30.81:15037", "adb", "devices"],
  "return_code": 0,
  "output": "List of devices attached\nemulator-5554\tdevice\n"
}
```

`adb devices` 执行失败、adb 不存在或超时时仍返回同结构响应，前端通过 `return_code` 和 `output` 判断命令结果；超时或未启动时 `return_code` 为 `null`。

## Workspace

### GET /workspace/browse — 浏览 workspace 目录

列出容器内 `/workspace` 下指定目录的文件和子目录，供前端文件浏览器使用。

**Query Params:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| path | string | `/workspace` | 容器内**绝对路径**，必须为 `/workspace` 或以 `/workspace/` 开头；不传则默认为 `/workspace` |

**Response (200):**

```json
{
  "path": "/workspace/entry/kscan-task-xxxxxxxx",
  "parent": "/workspace/entry",
  "items": [
    {"name": "subdir", "path": "/workspace/entry/kscan-task-xxxxxxxx/subdir", "is_dir": true, "size": null},
    {"name": "entry_scan_results.txt", "path": "/workspace/entry/kscan-task-xxxxxxxx/entry_scan_results.txt", "is_dir": false, "size": 1234}
  ]
}
```

- 返回的 `path` 和 `items[].path` 均为容器内绝对路径，可直接作为下次 `browse` 请求的 `path` 或其它接口（如 `entrylist`）的输入。
- `parent` 为 `null` 时表示已在 `/workspace` 根目录。
- 目录排在文件前面，按名称排序；文件的 `size` 为字节数，目录为 `null`。
- 路径穿越防护：经 `Path.resolve()` 后仍不在 `/workspace` 下 → **403**；路径不是绝对路径 → **400**。
- 路径不存在 **404**，路径为文件而非目录 **400**，无读权限 **403**。

### GET /workspace/read — 读取文件内容

读取 `/workspace` 下指定文件的文本内容，用于前端预览 `.md`、`.txt`、`.json`、`.log` 等文本文件。

**Query Params:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| path | string | (required) | 容器内绝对路径，必须以 `/workspace` 开头，指向一个文件 |
| raw | bool | false | 为 `true` 时直接返回 `text/plain` 原文，不包裹 JSON |

**Response (raw=false, 200):**

```json
{
  "path": "/workspace/audit/kscan-task-xxxxxxxx/report_gpu_ioctl.md",
  "name": "report_gpu_ioctl.md",
  "size": 4567,
  "content_type": "text/markdown",
  "content": "# GPU ioctl 漏洞审计报告\n\n..."
}
```

**Response (raw=true, 200):**

直接返回 `text/plain; charset=utf-8` 原文。

**错误码：**

| Status | 说明 |
|--------|------|
| 400 | 路径非绝对路径 / 路径指向目录而非文件 / 缺少 path 参数 |
| 403 | 路径穿越 / 无读权限 |
| 404 | 文件不存在 |
| 413 | 文件超过 2 MB 预览上限 |
| 500 | 读取 IO 错误 |

## Tasks

### POST /tasks — 创建扫描任务

创建后自动进入队列，由后台调度器拉取执行。

**Request Body:**

```json
{
  "title": "drivers/gpu ioctl 入口扫描",
  "pipeline_mode": "entry_audit_poc",
  "kernel_dir": "/workspace/kernel",
  "report_dir": null,
  "entrylist": null,
  "notes": null,
  "entry_threads": 8,
  "audit_threads": 6,
  "poc_threads": 4
}
```

`poc_only` 示例（直接复用已有漏洞报告目录或单个 Markdown 报告）：

```json
{
  "title": "验证历史 audit 报告",
  "pipeline_mode": "poc_only",
  "kernel_dir": "/workspace/kernel",
  "report_dir": "/workspace/audit/kscan-task-xxxxxxxx"
}
```

`entrylist` 示例（`audit_only` 模式，直接复用 entry stage 的 txt 产物）：

```json
{
  "title": "沿用历史 entry 结果做 audit",
  "pipeline_mode": "audit_only",
  "kernel_dir": "/workspace/kernel",
  "entrylist": "/workspace/entry/kscan-task-xxxxxxxx/entry_scan_results.txt"
}
```

文件内容格式（每行一条 `<func> <method>` 或 entry stage 产物的 `<func> [<method>]`，均被接受）：

```
gpu_ioctl ioctl
binder_ioctl ioctl
proc_sys_read read
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | string | yes | 任务标题 |
| pipeline_mode | enum | no | `entry_only` / `audit_only` / `poc_only` / `entry_audit_poc`（默认） |
| kernel_dir | string | conditional | 内核源码目录（容器内路径）。`poc_only` 模式必填；其它模式不传则使用默认 `/workspace/kernel` |
| report_dir | string | conditional | 漏洞报告目录或单个 Markdown 报告文件路径（容器内路径）。`poc_only` 模式必填；`entry_audit_poc` 模式不填时使用本任务 audit stage 输出目录 |
| device_ip | string | no | 兼容旧字段；PoC stage 不再依赖该字段。远端 ADB server 由 `/devices/adb/connect` 写入 `~/.bashrc` 的 `ADB_SERVER_SOCKET` 提供 |
| entrylist | string | no | 攻击入口清单文件路径（容器内绝对路径）。文本格式，每行 `<func> <method>` 或 `<func> [<method>]`（entry stage 输出的 txt 即此格式）。`audit_only` 模式必填；其他模式下若提供，audit stage 直接读取该文件；否则回退到 entry stage 输出的 `entry_scan_results.json`。常见取值：`/workspace/entry/{task_id}/entry_scan_results.txt` |
| notes | string | no | 备注 |
| entry_threads | int (1–32) | no | entry 阶段并行线程数，不传则使用服务默认值（`KERNEL_SCAN_ENTRY_THREADS`，默认 4） |
| audit_threads | int (1–32) | no | audit 阶段并行线程数，不传则使用服务默认值（`KERNEL_SCAN_AUDIT_THREADS`，默认 4） |
| poc_threads | int (1–16) | no | poc 阶段并行线程数，不传则使用服务默认值（`KERNEL_SCAN_POC_THREADS`，默认 2） |

**Response (200):**

```json
{
  "task_id": "kscan-task-xxxxxxxx",
  "attempt_id": "kscan-attempt-xxxxxxxx",
  "status": "queued"
}
```

### GET /tasks — 任务列表

按创建时间倒序分页返回。

**Query Params:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| page | int | 1 | 页码，从 1 开始 |
| per_page | int | 20 | 每页条数，最大 100 |

**Response (200):**

```json
{
  "items": [
    {
      "task_id": "kscan-task-xxxxxxxx",
      "title": "drivers/gpu ioctl 入口扫描",
      "pipeline_mode": "entry_audit_poc",
      "kernel_dir": "/workspace/kernel",
      "status": "running",
      "current_stage": "audit",
      "created_at": "2026-05-12T10:00:00Z",
      "started_at": "2026-05-12T10:00:01Z",
      "finished_at": null,
      "message": null
    }
  ],
  "total": 42,
  "page": 1,
  "per_page": 20
}
```

### GET /tasks/{task_id} — 任务详情

返回任务完整信息，`stage_runs` 为最新 attempt 的 entry/audit/poc 执行记录。

**Response (200):**

```json
{
  "task_id": "kscan-task-xxxxxxxx",
  "title": "drivers/gpu ioctl 入口扫描",
  "pipeline_mode": "entry_audit_poc",
  "kernel_dir": "/workspace/kernel",
  "status": "running",
  "current_stage": "audit",
  "latest_attempt_id": "kscan-attempt-xxxxxxxx",
  "attempt_count": 1,
  "notes": null,
  "created_by": "",
  "created_at": "2026-05-12T10:00:00Z",
  "updated_at": "2026-05-12T10:05:20Z",
  "started_at": "2026-05-12T10:00:01Z",
  "finished_at": null,
  "message": null,
  "stage_runs": [
    {
      "stage_run_id": "kscan-srun-xxxxxxxx",
      "attempt_id": "kscan-attempt-xxxxxxxx",
      "stage_name": "entry",
      "status": "succeeded",
      "return_code": 0,
      "started_at": "2026-05-12T10:00:01Z",
      "finished_at": "2026-05-12T10:02:40Z",
      "message": "entry scan completed, 23 entries",
      "metadata_json": "{\"entries_found\": 23, \"duration_seconds\": 158.74}"
    }
  ]
}
```

- `status` 取值：`queued` / `running` / `succeeded` / `partial_success` / `failed` / `cancel_requested` / `cancelled`
- `stage_runs[].status` 取值：`pending` / `running` / `succeeded` / `failed` / `skipped` / `cancelled` / `timed_out`
- `metadata_json` 是 stage 特定的元数据 JSON 字符串（entry 带 `entries_found`、audit 带 `reports_produced`、poc 带 `total_vuls`/`confirmed` 等）

**404** — 任务不存在。

### POST /tasks/{task_id}/cancel — 取消任务

请求取消排队中或运行中的任务。已完成/已取消的任务无法再取消。

**Responses:**

| Status | 说明 |
|--------|------|
| 200 | 已进入取消流程 |
| 400 | 任务不存在或已终态，无法取消 |

**200 Body:**

```json
{
  "task_id": "kscan-task-xxxxxxxx",
  "status": "cancel_requested"
}
```

### DELETE /tasks/{task_id} — 删除任务

删除任务及其全部 attempts / 阶段记录 / 事件 / 产物，并清理：

- `state_root/tasks/{task_id}/`（日志、执行状态）
- `workspace_root/entry/{task_id}/`（entry stage 产物）
- `workspace_root/audit/{task_id}/`（audit stage 产物，报告 + 日志）
- `workspace_root/poc/{task_id}/`（poc stage 产物，结果 + 日志）

仅当任务处于终态（`succeeded` / `partial_success` / `failed` / `cancelled`）时可删除。若仍在 `queued` / `running` / `cancel_requested` 状态，需先调用取消接口等待任务终止后再删除。

**Responses:**

| Status | 说明 |
|--------|------|
| 200 | 删除成功 |
| 404 | 任务不存在 |
| 409 | 任务未处于终态，拒绝删除 |

**200 Body:**

```json
{
  "task_id": "kscan-task-xxxxxxxx",
  "status": "deleted"
}
```

### POST /tasks/{task_id}/restart — 重启任务

重新运行一个已终态的任务。服务复用任务原有的 `pipeline_mode` / `kernel_dir` / `entrylist` / `report_dir` / 线程数等配置，新建一次 attempt（`attempt_no = attempt_count + 1`），并把任务状态置回 `queued`，由后台调度器拉取执行。`/tasks/{task_id}` 返回的 `stage_runs` 会切换到新 attempt 的记录。

**说明：**

- 仅当任务处于终态（`succeeded` / `partial_success` / `failed` / `cancelled`）时可重启；`queued` / `running` / `cancel_requested` 状态请先取消并等待终止。
- **不会清理** 已有产物目录（`workspace_root/{entry,audit,poc}/{task_id}/`），新执行会按原路径覆盖写入；如需干净环境请改用 `DELETE /tasks/{task_id}` 后重新创建。
- 历史 attempts / stage_runs / events 全部保留在数据库中，不会被删除。

**Request Body:** 无（空 body 即可）。

**Responses:**

| Status | 说明 |
|--------|------|
| 200 | 已创建新 attempt 并入队 |
| 404 | 任务不存在 |
| 409 | 任务未处于终态，拒绝重启 |

**200 Body:**

```json
{
  "task_id": "kscan-task-xxxxxxxx",
  "attempt_id": "kscan-attempt-yyyyyyyy",
  "status": "queued"
}
```

### GET /tasks/{task_id}/events — 事件流

支持游标分页，前端可轮询实现实时状态更新。

**Query Params:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| after_seq | int | 0 | 游标：只返回 event_seq > after_seq 的事件 |
| limit | int | 100 | 单次最多返回条数（max 500） |

**Response (200):**

```json
{
  "items": [
    {
      "event_seq": 1,
      "event_id": "kscan-evt-xxxxxxxx",
      "task_id": "kscan-task-xxxxxxxx",
      "attempt_id": "kscan-attempt-xxxxxxxx",
      "stage_name": "entry",
      "event_type": "stage.started",
      "level": "info",
      "message": "entry stage started",
      "payload_json": "{}",
      "created_at": "2026-05-12T10:00:01Z"
    }
  ],
  "next_cursor": 1
}
```

- `event_type` 常见取值：`stage.started` / `stage.completed` / `task.completed` / `task.failed` / `task.cancelled`
- `level` 取值：`debug` / `info` / `warning` / `error`
- `next_cursor` 为 `null` 表示暂无更多事件，稍后重试。

**404** — 任务不存在。

### GET /tasks/{task_id}/entry/result — 获取 entry 阶段文本结果

读取文件 `{workspace_root}/entry/{task_id}/entry_scan_results.txt`（每行形如 `func [method]`）。

**Query Params:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| format | string | `json` | `json` 返回结构化响应；`text` 直接返回 `text/plain` 原文件 |

**Response (format=json, 200):**

```json
{
  "task_id": "kscan-task-xxxxxxxx",
  "path": "/workspace/entry/kscan-task-xxxxxxxx/entry_scan_results.txt",
  "exists": true,
  "size": 1234,
  "content": "gpu_ioctl [ioctl]\nbinder_ioctl [ioctl]\n..."
}
```

- `format=json` 时：文件未生成或尚未写入返回 `exists=false`、`content=""`、`size=0`（便于前端轮询，不会 404）。
- `format=text` 时：文件不存在返回 **404**。
- 读文件 IO 错误统一返回 **500**。
- **404** — 任务不存在（同 `format`）。

## Stage Artifacts Layout

每个 stage 的产物都会落在 `workspace_root` 下按 stage 分组的目录（默认 `workspace_root=/workspace`，可由 `KERNEL_SCAN_WORKSPACE_ROOT` 覆盖）。

| Stage | 前端入参（仅影响输入） | 输出目录（服务固定约定） | 主要产物 |
|-------|-----------------------|--------------------------|----------|
| entry | `kernel_dir` | `workspace_root/entry/{task_id}/` | `entry.log`、`entry_scan_results.json`（结构化，供后续 stage 消费）、`entry_scan_results.txt`（`func [method]` 文本列表）、`entry_scan_progress.json`（断点续跑） |
| audit | `entrylist`（文件路径）、`kernel_dir` | `workspace_root/audit/{task_id}/` | `entrylist`（前端未指定路径时由 entry stage 输出规范化生成；前端已给路径时直接复用前端那份，不再在此目录生成）、`audit.log`（stage 日志）、`*.md`（Claude 生成的漏洞报告） |
| poc   | `report_dir`（目录或单个 `.md`，完整流水线默认取上一 stage 的 audit 目录）、`kernel_dir` | `workspace_root/poc/{task_id}/` | `poc.log`、`vullist`（断点续跑）、`vul_results/{report}/{VUL-N}/`（每个漏洞独立目录，含 `vulnerability.md`、`claude_response.md` 以及 Claude 生成的 PoC/验证报告）、`poc_results.json`（结构化统计，含 `output_dir`） |

说明：

- Entry/audit/poc 的线程数和模型不由前端路径决定，通过任务级覆盖字段（`entry_threads` / `audit_threads` / `poc_threads`）或服务级环境变量控制。
- POST `/tasks` 中的 `kernel_dir` 会透传给三个 stage。
- audit 的 `entrylist`：前端提供文件路径 → audit stage 直接以该路径调用 `ask_claude_kernaudit_v2.py --devlist <path>`（脚本 CLI 仍叫 `--devlist`，是历史名）；否则 audit stage 从 `/workspace/entry/{task_id}/entry_scan_results.json` 规范化生成 `/workspace/audit/{task_id}/entrylist`。
- entry stage 的 txt 产物 `/workspace/entry/{task_id}/entry_scan_results.txt` 可直接作为 `entrylist` 使用（`audit_only` 模式典型用法）。
- poc 的 ADB 设备：前端不再向任务创建接口传 ADB IP。`/devices/adb/connect` 会把远端 ADB server 写入 `~/.bashrc`，poc stage 启动时执行 `source ~/.bashrc && adb devices`，选择第一个 `device` 状态设备并设置 `ANDROID_SERIAL=<serial>`。如果没有在线设备，poc stage 直接失败并把错误写入任务/stage message。检查通过后，PoC 子进程同样通过 `bash -lc 'source ~/.bashrc && ...'` 启动。
- poc 的 `report_dir`：可传目录，也可传单个 `.md` 报告文件；单文件会被复制到本任务 `poc/input_reports/` 后再交给脚本处理。
- 删除任务时上述三个目录会一并被清理（见 `DELETE /tasks/{task_id}`）。

## Pipeline Modes

| Mode | Stages | Description |
|------|--------|-------------|
| `entry_audit_poc` | entry → audit → poc | 完整三阶段流水线（默认） |
| `entry_only` | entry | 仅扫描攻击入口 |
| `audit_only` | audit | 仅漏洞审计（需提供 entrylist 文件路径） |
| `poc_only` | poc | 仅 PoC 验证（需提供 `report_dir` 和 `kernel_dir`；ADB server 从 `~/.bashrc` 读取） |

## Task Status Flow

```
queued → running → succeeded / partial_success / failed
                 ↘ cancel_requested → cancelled
```

## Thread Parallelism

每个阶段的并行线程数支持两级配置：

1. **服务级默认值** — 通过环境变量或 `config.yaml` 设置
   - `KERNEL_SCAN_ENTRY_THREADS` (default: 4)
   - `KERNEL_SCAN_AUDIT_THREADS` (default: 4)
   - `KERNEL_SCAN_POC_THREADS` (default: 2)

2. **任务级覆盖** — 创建任务时通过 API 指定 `entry_threads` / `audit_threads` / `poc_threads`，仅对该任务生效

优先级：任务级 > 服务级默认值

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| KERNEL_SCAN_DATABASE_URL | sqlite:////.../kernel-scan.db | 数据库连接 |
| KERNEL_SCAN_STATE_ROOT | /var/lib/secflow-kernel-scan | 状态存储根目录 |
| KERNEL_SCAN_KERNEL_DIR | /workspace/kernel | 内核源码目录 |
| KERNEL_SCAN_WORKSPACE_ROOT | /workspace | Stage 产物输出根目录（各 stage 在此下按 `entry/` `audit/` `poc/` 分组） |
| KERNEL_SCAN_EXECUTION_MODE | claude_cli | 执行模式 |
| KERNEL_SCAN_CLAUDE_MODEL | zai-org/GLM-5 | 默认模型 |
| KERNEL_SCAN_MAX_PARALLEL_TASKS | 1 | 最大并行任务数 |
| KERNEL_SCAN_ENTRY_THREADS | 4 | entry 默认线程数 |
| KERNEL_SCAN_AUDIT_THREADS | 4 | audit 默认线程数 |
| KERNEL_SCAN_POC_THREADS | 2 | poc 默认线程数 |
| ANTHROPIC_API_KEY | — | Anthropic API Key |
| ANTHROPIC_BASE_URL | — | 自定义 API Base URL |
