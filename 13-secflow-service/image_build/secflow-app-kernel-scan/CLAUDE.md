# CLAUDE.md — secflow-app-kernel-scan

本文件记录该微服务的设计、运行时关键点，以及已踩过的坑与对应的修复思路，供后续会话快速进入上下文。

## 服务定位

将原本三个独立脚本（`ask_claude_entry.py` / `ask_claude_kernaudit_v2.py` / `ask_claude_poc.py`）封装成一个 FastAPI 微服务，容器化部署到 SecFlow 平台。三个脚本原封保留在镜像里（`/app/ask_claude_*.py`），stage worker 只是薄壳，用 `run_logged_command` 起子进程调用它们，同时接管日志流、心跳、取消和超时。

- API 前缀：`/api/app/kernel-scan`
- 监听端口：`8080`（compose 默认映射 `18081:8080`）
- 内核源码挂载路径：`/workspace/kernel`
- 状态根目录：`/var/lib/secflow-kernel-scan`
- Stage 产物根：`/workspace`（由 `KERNEL_SCAN_WORKSPACE_ROOT` 覆盖）
- 数据库：SQLite（WAL，`isolation_level=None` autocommit，`foreign_keys=ON`）
- 兼容 branch：`v2.1`

## Pipeline 模式

| Mode | Stages |
|------|--------|
| `entry_only` | entry |
| `audit_only` | audit（需 entrylist 文件路径） |
| `poc_only` | poc（需 `kernel_dir`、`report_dir`；ADB server 从 `~/.bashrc` 读取） |
| `entry_audit_poc`（默认） | entry → audit → poc |

常量定义在 `app/services/task_service.py:16` `PIPELINE_STAGES`。

## 代码结构

```
app/
├── main.py                     FastAPI 入口 + lifespan
├── schemas.py
├── api/
│   ├── devices.py              /devices/adb/connect（设置 ADB_SERVER_SOCKET 并返回 adb devices 结果）
│   ├── health.py               /health /ready
│   ├── workspace.py            /workspace/browse（只接受绝对路径，必须以 /workspace 开头，默认 /workspace）
│   └── tasks.py                任务 CRUD + 事件流 + entry 文本结果
├── core/
│   ├── config.py               ServiceConfig (yaml + env，含 workspace_root)
│   ├── ids.py
│   └── time_utils.py           utc_now_z()
├── db/
│   ├── database.py             sqlite3 wrapper
│   └── migrations/0001_init.sql
├── services/
│   ├── adb_service.py          ADB_SERVER_SOCKET / devices / get-state / getprop 复用服务
│   ├── task_service.py         任务 CRUD / claim / delete（清 state + workspace 三个 stage 目录）
│   ├── execution_service.py    流水线编排 + 心跳 pump
│   └── event_service.py
└── workers/
    ├── runner.py               run_logged_command / StageContext / StageHooks
    ├── scheduler.py            ThreadPoolExecutor 调度
    ├── stage_entry.py          子进程调 ask_claude_entry.py
    ├── stage_audit.py          子进程调 ask_claude_kernaudit_v2.py
    └── stage_poc.py            子进程调 ask_claude_poc.py

ask_claude_entry.py             /app/ 下，参数化版（--kernel-dir / --output-dir / --threads / --model）
ask_claude_kernaudit_v2.py      /app/ 下，参数化版（--devlist / --kernel-dir / --report-dir / --threads / --model / --method-filter）
ask_claude_poc.py               /app/ 下，参数化版（--report-dir / --kernel-dir / --device-ip / --vullist / --output-dir / --results-json / --model）
```

## 数据库表（`app/db/migrations/0001_init.sql`）

- `kernel_scan_tasks` — 任务主表
- `kernel_scan_attempts` — 每次执行尝试（带 `worker_id` / `lease_expires_at` / `heartbeat_at`）
- `kernel_scan_stage_runs` — stage 级执行记录（entry/audit/poc）
- `kernel_scan_events` — 事件流（`event_seq` 作为游标）
- `kernel_scan_artifacts` — 产物登记

`tasks → attempts → stage_runs / events / artifacts` 级联删除。

## 任务状态流

```
queued → running → succeeded / partial_success / failed
                 ↘ cancel_requested → cancelled
```

`TERMINAL_TASK_STATUSES = {"succeeded", "partial_success", "failed", "cancelled"}`（`task_service.py:23`）。
只有终态任务能被 `DELETE /tasks/{id}` 删除，否则返回 409。

## API 一览

详见 `API.md`。核心端点：

| Method | Path | 关键点 |
|--------|------|--------|
| GET | /workspace/browse | 前端文件浏览器；`path` 为绝对路径（默认 `/workspace`），返回值也是绝对路径，可直接回传 |
| POST | /devices/adb/connect | 前端发空请求即可，后端固定设置 `ADB_SERVER_SOCKET=tcp:172.31.30.81:15037`，执行 `adb devices`，且只有 `adb shell` 成功后才写入 `~/.bashrc`；接口只返回 `adb devices` 命令结果 |
| POST | /tasks | `pipeline_mode` / `kernel_dir` / `entrylist` / `report_dir` / 三个 `*_threads` 可选覆盖；PoC 设备来自 `~/.bashrc` |
| GET | /tasks | 分页 |
| GET | /tasks/{id} | 附带 `stage_runs` |
| POST | /tasks/{id}/cancel | 仅 queued/running 可取消 |
| POST | /tasks/{id}/restart | 仅终态可重启；复用原配置新建 attempt，task 回 queued；不清理产物目录 |
| DELETE | /tasks/{id} | 仅终态可删，级联删 DB + 清理 `state_root/tasks/{id}` + `/workspace/{entry,audit,poc}/{id}/` |
| GET | /tasks/{id}/events | `after_seq` 游标分页 |
| GET | /tasks/{id}/entry/result | entry 文本结果，`?format=text` 直出纯文本 |

## Stage 产物布局（workspace_root 默认 `/workspace`）

| Stage | 前端入参 | 输出目录 | 关键产物 |
|-------|----------|----------|----------|
| entry | `kernel_dir` | `/workspace/entry/{task_id}/` | `entry.log`、`entry_scan_results.json`、`entry_scan_results.txt`、`entry_scan_progress.json` |
| audit | `entrylist`（文件路径，典型值 `/workspace/entry/{task}/entry_scan_results.txt`）、`kernel_dir` | `/workspace/audit/{task_id}/` | `entrylist`（前端未给路径时由 entry stage 输出规范化生成）、`audit.log`、Claude 写的 `*.md` 报告 |
| poc   | `report_dir`（目录或单个 `.md`；完整流水线默认前一 stage 的 audit 目录）、`kernel_dir` | `/workspace/poc/{task_id}/` | `poc.log`、`vullist`、`vul_results/{report}/{VUL-N}/`（每漏洞独立目录，含 PoC/验证报告）、`poc_results.json` |

Stage 之间的数据契约：

- audit：前端 `entrylist` 为文件路径时直接以该文件调 `ask_claude_kernaudit_v2.py --devlist <path>`（脚本 CLI 仍叫 `--devlist`，保留历史名，API 层已改叫 `entrylist`）；未提供时从 `/workspace/entry/{task}/entry_scan_results.json` 规范化生成 `/workspace/audit/{task}/entrylist`。`devlist_json` 列（历史名）现在存的是**路径字符串**而非 JSON，`execution_service` 直接当路径用。
- entry stage 的 txt 产物 `/workspace/entry/{task}/entry_scan_results.txt` 可直接作为 `entrylist`，格式是 `func [method]`，audit 脚本的 `method_filter` substring 匹配能吃下这个括号。
- poc 读 `/workspace/audit/{task}/` 下的 `*.md`（或前端显式 `report_dir`），扫出 `VUL-N` 逐条验证。`poc_only` 必须由前端提供 `kernel_dir` 和 `report_dir`；ADB server 地址由 `/devices/adb/connect` 写入 `~/.bashrc`。poc stage 启动时执行 `source ~/.bashrc && adb devices`，选择第一个 `device` 状态设备；没有在线设备时直接失败并把错误写入任务/stage message。检查通过后用 `bash -lc 'source ~/.bashrc && ...'` 启动脚本，并设置 `ANDROID_SERIAL=<serial>`。

## 调度 & 执行

- `workers/scheduler.py` 用 ThreadPoolExecutor 拉 `kernel_scan_attempts.status='queued'` 的记录交给 `ExecutionService.run_attempt`。
- `services/execution_service.py:_run_stage` 为单个 stage 建立 `StageHooks`（heartbeat + cancel check），依次跑 entry/audit/poc。
- 每个 stage worker 是子进程外壳：`run_logged_command` 起 `python3 -u /app/ask_claude_*.py ...`，stdout/stderr 实时写日志，poll-loop 自带 heartbeat、取消（SIGTERM→SIGKILL）和超时。
- 真正的并行在脚本内部 `ThreadPoolExecutor`，线程数通过 CLI `--threads` 由 stage worker 透传，来源是任务级 override > 服务级默认值。

线程数配置两级（任务级 > 服务级，见 `API.md`）：
- `KERNEL_SCAN_ENTRY_THREADS` / `AUDIT_THREADS` / `POC_THREADS`
- `entry_threads` / `audit_threads` / `poc_threads` 字段

## Claude CLI 调用形态（`app/workers/runner.py`）

- `run_logged_command` — `subprocess.Popen` + `selectors` 实时写日志，**自带 heartbeat pump**（每 `heartbeat_interval_seconds` 调 `hooks.heartbeat()`），处理取消和超时。这是 stage worker 调脚本时使用的唯一路径。
- `run_claude_prompt` / `build_claude_command` — 旧的同步 capture_output 形态，目前仍保留以便其它代码或将来内联调用使用，但不再被 stage 调用。每条 Claude prompt 现在都从脚本内部直接 fork `claude` 进程。
- 因此 stage 级心跳由 `_run_stage` 启动的 heartbeat pump + `run_logged_command` 内部 pump 双重保证；脚本内部的 Claude 调用不再各自发心跳。

## 关键配置默认值（`app/core/config.py`）

- `lease_duration_seconds=30`
- `heartbeat_interval_seconds=5`
- `scheduler_tick_interval_seconds=1.0`
- `KERNEL_SCAN_MAX_PARALLEL_TASKS=1`
- `KERNEL_SCAN_CLAUDE_MODEL=zai-org/GLM-5`
- `KERNEL_SCAN_EXECUTION_MODE=claude_cli`

环境变量清单见 `API.md` 末尾和 `Dockerfile` 的 `ENV` 段。

## 容器启动 & Claude CLI 免初始化

**Dockerfile 关键点：**

- 基础镜像默认走华为云 Docker Hub mirror：`swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/library/python:3.11-slim`，强制 `linux/amd64` 平台（docker-compose.yml `platform: linux/amd64`）；可用 `PYTHON_BASE_IMAGE` 覆盖回官方或其它镜像。注意该 mirror 当前没有 `3.11-slim-bookworm` manifest。
- 从 Node 基础镜像多阶段拷贝 Node 运行时，默认 `swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/library/node:22-bookworm-slim`，可用 `NODE_BASE_IMAGE` 覆盖
- apt 装 `bash ca-certificates curl git iproute2 jq procps ripgrep tini clangd unzip`
- `npm install -g @anthropic-ai/claude-code`
- 非 root 用户 `scanner` (uid 1000)
- `skills/` 和 `agents/` 拷进 `/home/scanner/.claude/`
- 镜像内用 `claude plugin install clangd-lsp@claude-plugins-official` 预装插件
- `ENTRYPOINT /usr/bin/tini -- /app/entrypoint.sh`，`CMD python3 -m app.main`

**Android 工具链（adb / fastboot / NDK）：**

构建前推荐运行 `./scripts/prepare-android-tools.sh`，把下载产物缓存在 `./tools/`。Dockerfile 构建时优先使用缓存文件；缓存不存在时，也会在构建阶段从 Google 官方下载并安装：

| 构建参数 | 默认地址 | 安装目标 |
|---|---|---|
| `ANDROID_PLATFORM_TOOLS_URL` | `https://dl.google.com/android/repository/platform-tools-latest-linux.zip` | `/opt/android-tools/adb`、`/opt/android-tools/fastboot` |
| `ANDROID_NDK_URL` | `https://dl.google.com/android/repository/android-ndk-r29-linux.zip` | `/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/` |

PATH 已包含 `/opt/android-tools` 和 NDK clang 路径，容器内直接 `adb`、`fastboot`、`aarch64-linux-android21-clang` 可用。`entrypoint.sh` 仍保留从 `/mnt/archives/` 解压的旧部署兜底逻辑，但 docker-compose 默认不再挂载 `./tools`。

**模板文件（仓库根提供，不要缩减，直接拷贝）：**

- `.claude.json` → Dockerfile COPY 成 `/app/claude.json.template`
- `settings.json` → Dockerfile COPY 成 `/app/settings.json.template`

**`entrypoint.sh` 首启动逻辑（cp-then-patch）：**

1. 若 `~/.claude.json` / `~/.claude/settings.json` 不存在，从 `/app/*.template` 拷贝。
2. 用 `jq` 对 `~/.claude.json` 打三个运行时补丁（不能在模板里写死）：
   - 把当前 `$ANTHROPIC_API_KEY` 的 sha256 前 20 字符塞进 `customApiKeyResponses.approved`；
   - 对 `/workspace` / `/workspace/kernel` / `/app` 写入 `projects[path].hasTrustDialogAccepted=true` 等空骨架字段；
   - `hasCompletedOnboarding=true`、`lastOnboardingVersion=$(claude --version | awk '{print $1}')`。
3. 确保 `KERNEL_SCAN_STATE_ROOT` 存在。
4. 若镜像内不存在 Android 工具且旧部署挂载了 `/mnt/archives/*.zip`，从挂载 zip 解压兜底。
5. `exec "$@"` 交给 CMD。

> 为什么需要这些 patch：模板里那几个字段是"构建机器当时的值"，runtime 换了 API key / 装了新版本 CLI 就会触发交互式 setup 再次弹出。

## 已修复 / 已踩坑记录

### 删除任务接口

- `task_service.delete_task(task_id) → "deleted" | "not_found" | "busy"`
- 事务内 `BEGIN IMMEDIATE`，非终态直接 ROLLBACK 返 busy
- DB 删除后用 `shutil.rmtree(state_root/tasks/{task_id})` 清产物；OSError 仅 warning，不影响接口
- `DELETE /tasks/{id}` 映射：`busy → 409`，`not_found → 404`，成功返回 `{task_id, status:"deleted"}`

### `attempt lost (lease expired)` 的根因与修复

**症状：** 创建扫描任务后，`GET /tasks/{id}` 很快变成 `status=failed`、`message="attempt lost (lease expired)"`。

**根因：** 当初 `_run_stage` 只在进入 stage 前调一次 `hooks.heartbeat()`，而 stage 内部的 per-item Claude 调用是同步 `subprocess.run`（不发心跳）。Claude 响应一旦超过 `lease_duration_seconds=30`，`TaskService.recover_expired_attempts()` 就把 attempt 标成 `lost`，任务随之 `failed`。

**修复（当前形态）：**
1. `execution_service._run_stage` 中启动守护线程 `_heartbeat_pump`，每 `heartbeat_interval_seconds` 续租；stage 结束（正常/异常）在 `finally` 里 `stop_event.set()` + `pump.join(timeout=5.0)`。
2. Stage 从 "in-proc 同步调 claude" 改成 "起 `ask_claude_*.py` 子进程 + `run_logged_command`"，后者本身的 poll-loop 每 `heartbeat_interval_seconds` 也调 `hooks.heartbeat()`。两条路径叠加，期间不会再出现长于 `lease_duration_seconds` 的静默。

**非根因但同时观察到的：** docker logs 里偶见 `FOREIGN KEY constraint failed` 来自 `_fail_attempt` 尝试给已被级联删除的 task 追加事件。目前未修，属于删除和失败的 race，等真实复现再处理。

## 开发 / 验证命令

使用 `sothoth` conda 环境：

```bash
source /home/runshine/miniconda3/etc/profile.d/conda.sh && conda activate sothoth
cd 13-secflow-service/image_build/secflow-app-kernel-scan
pip install -r requirements.txt
python -m app.main                                              # 本地启动
curl localhost:8080/api/app/kernel-scan/health                  # 健康检查
```

容器：

```bash
docker compose up -d --build                                     # 起服务
docker compose logs -f secflow-app-kernel-scan                   # 看日志
```

冒烟路径：`/workspace/kernel/test`（容器内内置若干 .c 文件），用 `entry_only` 模式先过。

## 仍待处理 / 值得留意

- 心跳 race：`_fail_attempt` 写事件时，task 可能刚被级联删除，导致 FK 失败。可考虑在 `_fail_attempt` 里先判断 task 是否还在，或写 event 用 `INSERT OR IGNORE`。
- stage worker 若自身抛异常，`_run_stage` 的 `finally` 会保证停 pump，但 `_persist_stage_result` 不会被调用——靠外层 `_fail_attempt` 兜底。异常路径下 stage_run 行可能停留在 `running` 状态，前端展示需注意。
- `run_claude_prompt` 目前没有 timeout 默认值；长任务要么由 stage 内部控制要么依赖调用方传 `timeout`。后续可能补服务级默认。
