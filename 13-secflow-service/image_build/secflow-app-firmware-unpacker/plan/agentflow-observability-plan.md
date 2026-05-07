# 嵌入 AgentFlow 后的可观测性保障方案

编写日期：2026-05-07

## 0. 执行摘要

嵌入 AgentFlow 后，系统可观测性需要从"单进程 Python 函数调用"模式升级为"多节点 Agent 编排"模式。本文梳理 **已有能力**、**识别缺口**，并给出分阶段增强方案，确保生产灰度和切换期间运维可以：

1. **定位**：通过 task_id 追踪到 AgentFlow run → 节点 → trace → 原始输出
2. **量化**：知道每次解包的耗时分布、token 消耗、成功率、重试次数
3. **告警**：失败率/耗时/token 超限时自动通知
4. **回溯**：从失败任务中提取根因（哪个节点失败、失败原因、agent 原始输出）

---

## 1. 已有的可观测性能力

### 1.1 AgentFlow 内置层

| 能力 | 位置 | 说明 |
|---|---|---|
| **NormalizedTraceEvent** | `agentflow/specs.py` | 统一 trace 事件模型：`node_id`, `agent`, `attempt`, `source`, `kind`, `title`, `content`, `raw` |
| **多 Agent Trace Parser** | `agentflow/traces.py` | Codex/Claude/Kimi/Pi/Generic 五种 parser，将各 agent CLI 的 JSON-stream 输出规范化为 `NormalizedTraceEvent` |
| **RunStore** | `agentflow/store.py` | 每次运行生成 `run.json`（状态/节点/起止时间）、`events.jsonl`（事件流）、`nodes/<node_id>/`（节点输出+trace） |
| **Orchestrator 事件** | `agentflow/orchestrator.py` | run_started / node_started / node_completed / run_completed 等生命周期事件 |
| **GraphOptimizer** | `agentflow/graph_optimizer.py` | 可视化图结构、优化迭代轮数 |
| **Web Dashboard** | `agentflow/web/` | AgentFlow 自带的简易 Web UI 展示运行状态 |

### 1.2 应用服务层

| 能力 | 位置 | 说明 |
|---|---|---|
| **结构化 JSON 日志** | `app/logging_utils.py` | `JsonFormatter` + `ContextFilter`，支持 `task_id`/`project_id`/`worker_id` 等上下文字段注入 |
| **DB 任务模型** | `app/model.py` | `UnpackTask` 含 `status`, `result_status`, `result_message`, `rounds`, `agentflow_run_id`, `engine_error`, `run_path`, `started_at`, `completed_at` 等 |
| **AgentFlow 状态 API** | `app/api/firmware.py` | `GET .../tasks/{id}/agentflow` → 读取 `run.json` 返回 run 状态、节点列表 |
| **Pod 资源监控** | `app/services/pod_metrics.py` | 通过 K8s Metrics API 获取 Pod CPU/内存 |
| **Worker 心跳与集群快照** | `app/services/worker.py` | 心跳注册、活跃任务数、孤儿任务回收、集群快照 API |
| **健康检查** | `app/api/firmware.py` | `/health` 和 `/ready` 端点 |
| **运行产物** | `app/agentflow_runner.py` | `agentflow_run_id.txt`, `final_result.json`, `tokens_summary.json`, stage 日志文件 |

### 1.3 基础设施层

| 能力 | 位置 | 说明 |
|---|---|---|
| **K8s Deployment/Service** | `k8s-deployment.yaml`, `k8s-service.yaml` | 标准化部署，支持滚动更新和回滚 |
| **ConfigMap** | `k8s-configmap.yaml` | 运行时配置外部化 |
| **ServiceAccount** | `k8s-serviceaccount.yaml` | Pod 身份，用于 K8s API 调用（如 metrics） |

---

## 2. 可观测性缺口分析

### 2.1 🔴 关键缺口

| # | 缺口 | 影响 | 当前状态 |
|---|---|---|---|
| G1 | **Token 消耗聚合为空** | 无法量化 LLM 成本；迁移计划明确标注"token summary 目前仍是占位" | `tokens_summary.json` 为空壳结构 |
| G2 | **节点级耗时不可查** | 只能看任务整体耗时，无法区分 preprocess/skill_match/executor/reviewer 各阶段耗时 | `run.json` 有节点状态但无 API 暴露耗时 |
| G3 | **Trace 事件未接入应用日志** | AgentFlow 的 `NormalizedTraceEvent` 只写入文件，不进入应用结构化日志流；排查时需登录 Pod 读文件 | runner 仅读取最终结果，未桥接 trace |
| G4 | **无告警机制** | 失败率飙升、节点超时、token 超限无自动通知 | 无 any alerting 代码或配置 |

### 2.2 🟡 中等缺口

| # | 缺口 | 影响 | 当前状态 |
|---|---|---|---|
| G5 | **AgentFlow API 返回信息有限** | `/agentflow` 端点只返回 `run.json` 的 `status` 和 `nodes`，不返回节点错误详情、trace 摘要 | 需登录 Pod 查看 |
| G6 | **集群级 AgentFlow 运行指标缺失** | `get_cluster_snapshot()` 返回任务计数和 Worker 状态，但不包含 AgentFlow 运行数/并发/排队 | 无法判断 AgentFlow 是否过载 |
| G7 | **Run 清理策略未生效** | `AgentFlowConfig.cleanup_runs_retention_days` 已配置但 runner 中未实现清理逻辑 | 磁盘可能无限增长 |
| G8 | **取消事件可观测性不足** | 取消操作只标记 DB `cancelled`，不记录取消时 AgentFlow run 处于哪个节点 | 难以分析取消原因 |

### 2.3 🟢 低优先级缺口

| # | 缺口 | 影响 |
|---|---|---|
| G9 | 无 OpenTelemetry/Metrics 导出 | 无法接入 Grafana/Prometheus 生态 |
| G10 | AgentFlow Web Dashboard 未与主服务集成 | 需单独部署和访问 |
| G11 | 无实时任务进度推送（WebSocket/SSE） | 前端只能轮询 |

---

## 3. 分阶段增强方案

### Phase 1：补齐关键可观测性（灰度前必须完成）

> 目标：让灰度期间能定位问题、量化成本

#### 3.1.1 Token 消耗聚合 [G1]

**改动文件**：`app/agentflow_runner.py`

**方案**：在 runner 等待 run 完成后，遍历 `run/agentflow/runs/<run_id>/traces/` 下各节点的 trace 文件，提取 token 用量并聚合。

```python
def _aggregate_token_summary(run_dir: Path) -> dict:
    """从 AgentFlow trace 文件中聚合 token 消耗。"""
    total_prompt = 0
    total_completion = 0
    node_tokens: dict[str, dict] = {}

    traces_dir = run_dir / "traces"
    if not traces_dir.is_dir():
        return {"total_prompt_tokens": 0, "total_completion_tokens": 0, "nodes": {}}

    for trace_file in sorted(traces_dir.glob("*.jsonl")):
        node_id = trace_file.stem
        prompt_tokens = 0
        completion_tokens = 0
        for line in trace_file.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
                raw = event.get("raw") or {}
                usage = raw.get("usage") or {}
                prompt_tokens += int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
                completion_tokens += int(usage.get("completion_tokens") or usage.get("output_tokens") or 0)
            except (json.JSONDecodeError, ValueError):
                continue
        if prompt_tokens or completion_tokens:
            node_tokens[node_id] = {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            }
            total_prompt += prompt_tokens
            total_completion += completion_tokens

    return {
        "total_prompt_tokens": total_prompt,
        "total_completion_tokens": total_completion,
        "total_tokens": total_prompt + total_completion,
        "nodes": node_tokens,
    }
```

在 `run_unpack_agentflow()` 的 result adapter 阶段调用，写入 `tokens_summary.json` 并将总量写入 DB（可新增 `token_count` 字段或复用 `engine_error` 同级字段）。

#### 3.1.2 节点级耗时 API [G2]

**改动文件**：`app/api/firmware.py`, `app/agentflow_runner.py`

**方案**：增强 `_get_task_agentflow_status()` 返回每个节点的 `started_at`/`completed_at`/`duration_seconds`/`status`/`error`。

```python
def _get_task_agentflow_status(task_id: str) -> dict:
    # ... 现有逻辑读取 run_json ...
    nodes_detail = []
    if isinstance(run_json, dict):
        for node in (run_json.get("nodes") or []):
            node_info = {
                "node_id": node.get("task_id") or node.get("id"),
                "status": node.get("status"),
                "started_at": node.get("started_at"),
                "completed_at": node.get("completed_at"),
                "error": node.get("error") or node.get("failure_reason"),
            }
            # 计算耗时
            if node_info["started_at"] and node_info["completed_at"]:
                try:
                    from datetime import datetime
                    start = datetime.fromisoformat(str(node_info["started_at"]))
                    end = datetime.fromisoformat(str(node_info["completed_at"]))
                    node_info["duration_seconds"] = (end - start).total_seconds()
                except (ValueError, TypeError):
                    node_info["duration_seconds"] = None
            else:
                node_info["duration_seconds"] = None
            nodes_detail.append(node_info)

    return {
        "task_id": task_id,
        "agentflow_run_id": run_id,
        "run_path": run_path or None,
        "status": run_json.get("status") if isinstance(run_json, dict) else None,
        "nodes": nodes_detail,
        "run": run_json,
    }
```

#### 3.1.3 Trace 事件桥接到应用日志 [G3]

**改动文件**：`app/agentflow_runner.py`

**方案**：在 runner 等待循环中，读取新增的 `events.jsonl` 事件，将关键事件（`node_completed`, `node_failed`, `run_completed`）以结构化日志输出。

```python
import logging

logger = logging.getLogger("app.agentflow_runner")

def _bridge_trace_events(run_dir: Path, last_event_offset: int) -> int:
    """将 AgentFlow 事件桥接到应用日志。"""
    events_file = run_dir / "events.jsonl"
    if not events_file.is_file():
        return last_event_offset

    lines = events_file.read_text(encoding="utf-8").splitlines()
    for i in range(last_event_offset, len(lines)):
        line = lines[i].strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        kind = event.get("kind") or event.get("type") or ""
        node_id = event.get("node_id") or event.get("task_id") or ""

        if "node_completed" in kind or "node_failed" in kind:
            logger.info(
                "agentflow_node_event",
                extra={
                    "agentflow_event": kind,
                    "node_id": node_id,
                    "status": event.get("status"),
                    "duration": event.get("duration_seconds"),
                    "error": event.get("error"),
                },
            )
        elif "run_completed" in kind:
            logger.info(
                "agentflow_run_completed",
                extra={
                    "agentflow_run_id": event.get("run_id"),
                    "status": event.get("status"),
                    "total_duration": event.get("total_duration_seconds"),
                },
            )

    return len(lines)
```

在等待循环中周期调用：

```python
last_offset = 0
while not run_done:
    # ... cancel_check ...
    last_offset = _bridge_trace_events(run_dir, last_offset)
    time.sleep(poll_interval)
# 最终再桥接一次，确保不遗漏
_bridge_trace_events(run_dir, last_offset)
```

这样，应用日志中会自动包含 AgentFlow 关键事件，可以用现有日志平台（ELK/Loki 等）检索。

### Phase 2：增强可观测性（灰度期间同步完成）

> 目标：降低运维排查成本，防止资源泄漏

#### 3.2.1 增强 AgentFlow API 返回 [G5]

在 `/agentflow` 端点中增加：
- `failed_nodes`：失败节点列表及错误信息
- `token_summary`：从 `tokens_summary.json` 读取
- `trace_files`：可用 trace 文件路径列表

#### 3.2.2 集群 AgentFlow 指标 [G6]

在 `get_cluster_snapshot()` 中增加：
- `agentflow_active_runs`：当前活跃 AgentFlow run 数
- `agentflow_max_concurrent`：配置的最大并发数
- `agentflow_runs_dir_usage_mb`：runs 目录磁盘占用

#### 3.2.3 Run 清理实现 [G7]

**改动文件**：`app/services/worker.py` 或 `app/agentflow_runner.py`

在 heartbeat 循环或独立定时任务中，清理超过 `cleanup_runs_retention_days` 的 AgentFlow run 目录：

```python
def cleanup_agentflow_runs() -> None:
    """清理过期的 AgentFlow run 目录。"""
    from app.config import get_config

    cfg = get_config()
    retention_days = cfg.agentflow.cleanup_runs_retention_days
    if retention_days <= 0:
        return

    runs_dir = Path(cfg.agentflow.runs_dir)
    if not runs_dir.is_dir():
        return

    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    for run_path in runs_dir.iterdir():
        if not run_path.is_dir():
            continue
        run_json = run_path / "run.json"
        if not run_json.is_file():
            continue
        try:
            data = json.loads(run_json.read_text(encoding="utf-8"))
            completed = data.get("completed_at")
            if completed and datetime.fromisoformat(str(completed)) < cutoff:
                shutil.rmtree(run_path, ignore_errors=True)
                logger.info("cleaned agentflow run: %s", run_path.name)
        except Exception as exc:
            logger.warning("failed to clean agentflow run %s: %s", run_path.name, exc)
```

#### 3.2.4 取消事件记录 [G8]

在 `run_unpack_agentflow()` 取消分支中增加结构化日志：

```python
if should_cancel:
    current_nodes = _read_current_node_status(run_dir)
    logger.warning(
        "agentflow_run_cancelled",
        extra={
            "task_id": task_id,
            "agentflow_run_id": run_id,
            "current_nodes": current_nodes,
            "cancel_reason": "user_cancelled",
        },
    )
    orchestrator.cancel(run_id)
```

### Phase 3：接入外部可观测性生态（生产稳定后）

> 目标：与平台监控体系打通

#### 3.3.1 Prometheus Metrics 导出 [G9]

**新增文件**：`app/metrics.py`

```python
from prometheus_client import Counter, Histogram, Gauge

TASK_TOTAL = Counter(
    "fw_unpack_tasks_total",
    "Total firmware unpack tasks",
    ["status"],  # success, failed, cancelled
)

TASK_DURATION = Histogram(
    "fw_unpack_task_duration_seconds",
    "Task duration in seconds",
    ["status"],
    buckets=[60, 300, 600, 1200, 1800, 3600],
)

AGENTFLOW_NODE_DURATION = Histogram(
    "fw_unpack_agentflow_node_duration_seconds",
    "AgentFlow node duration in seconds",
    ["node_id", "status"],
    buckets=[30, 60, 120, 300, 600, 900, 1800],
)

AGENTFLOW_TOKEN_TOTAL = Counter(
    "fw_unpack_agentflow_tokens_total",
    "AgentFlow token consumption",
    ["node_id", "token_type"],  # token_type: prompt, completion
)

AGENTFLOW_ACTIVE_RUNS = Gauge(
    "fw_unpack_agentflow_active_runs",
    "Currently active AgentFlow runs",
)
```

在 FastAPI 中暴露 `/metrics` 端点：

```python
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

@router.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
```

在 runner 中埋点：

```python
# 任务完成时
TASK_TOTAL.labels(status=result_status).inc()
TASK_DURATION.labels(status=result_status).observe(duration_seconds)

# 节点完成时
AGENTFLOW_NODE_DURATION.labels(node_id=node_id, status=node_status).observe(node_duration)
AGENTFLOW_TOKEN_TOTAL.labels(node_id=node_id, token_type="prompt").inc(prompt_tokens)
AGENTFLOW_TOKEN_TOTAL.labels(node_id=node_id, token_type="completion").inc(completion_tokens)
```

#### 3.3.2 OpenTelemetry Trace 集成 [G9 扩展]

如平台已有 OpenTelemetry 基础设施，可进一步：

```python
from opentelemetry import trace

tracer = trace.get_tracer("firmware-unpacker")

def run_unpack_agentflow(...):
    with tracer.start_as_current_span("agentflow_run") as span:
        span.set_attribute("task_id", task_id)
        span.set_attribute("firmware_path", firmware_path)
        # ... 各节点可创建 child span ...
```

#### 3.3.3 实时进度推送 [G11]

通过 SSE 或 WebSocket 将 AgentFlow 事件实时推送到前端：

```python
from fastapi import WebSocket

@router.websocket("/ws/tasks/{task_id}/agentflow/stream")
async def agentflow_stream(websocket: WebSocket, task_id: str):
    await websocket.accept()
    # 监听 events.jsonl 增量，推送新事件
    ...
```

---

## 4. 可观测性全景图

```
┌─────────────────────────────────────────────────────────────────┐
│                     前端 / 运维平台                              │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ 任务列表  │  │ 任务详情   │  │ Grafana  │  │ AlertManager  │  │
│  └────┬─────┘  └─────┬─────┘  └────┬─────┘  └──────┬────────┘  │
└───────┼──────────────┼──────────────┼────────────────┼───────────┘
        │              │              │                │
┌───────┴──────────────┴──────────────┴────────────────┴───────────┐
│                     API Layer (FastAPI)                           │
│  ┌──────────┐  ┌───────────────┐  ┌──────────┐  ┌────────────┐  │
│  │ /tasks   │  │ /agentflow    │  │ /metrics  │  │ /health    │  │
│  │ /cluster │  │ /resource     │  │ (P3)      │  │ /ready     │  │
│  └────┬─────┘  └──────┬────────┘  └────┬─────┘  └────────────┘  │
└───────┼───────────────┼────────────────┼─────────────────────────┘
        │               │                │
┌───────┴───────────────┴────────────────┴─────────────────────────┐
│                   Application Layer                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ task_manager │  │ agentflow    │  │ 结构化日志 (JSON)     │   │
│  │   worker     │  │   _runner    │  │ → stdout → ELK/Loki  │   │
│  └──────┬───────┘  └──────┬───────┘  └──────────────────────┘   │
└─────────┼─────────────────┼──────────────────────────────────────┘
          │                 │
┌─────────┴─────────────────┴──────────────────────────────────────┐
│                   AgentFlow Layer                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ Orchestrator │  │ RunStore     │  │ TraceParsers         │   │
│  │   events     │  │  run.json    │  │  Codex/Claude/Kimi/  │   │
│  │              │  │  events.jsonl│  │  Pi/Generic           │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
          │
┌─────────┴────────────────────────────────────────────────────────┐
│                   Infrastructure Layer                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ DB (SQLite/  │  │ K8s Metrics  │  │ 文件系统              │   │
│  │   MySQL)     │  │   API        │  │  run/agentflow/runs/ │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 5. 日志规范

### 5.1 结构化日志字段

嵌入 AgentFlow 后，应用日志应包含以下上下文字段：

| 字段 | 来源 | 示例 |
|---|---|---|
| `task_id` | ContextFilter | `"abc-123"` |
| `project_id` | ContextFilter | `"proj-456"` |
| `worker_id` | ContextFilter | `"pod-name-7d8f"` |
| `agentflow_run_id` | runner | `"run-789"` |
| `agentflow_event` | trace bridge | `"node_completed"` |
| `node_id` | trace bridge | `"generic_executor"` |
| `duration_seconds` | trace bridge | `42.5` |
| `token_count` | token summary | `15000` |

### 5.2 关键日志事件

| 事件 | 级别 | 触发时机 |
|---|---|---|
| `agentflow_run_started` | INFO | runner 提交 pipeline 后 |
| `agentflow_node_event` | INFO | 节点完成/跳过 |
| `agentflow_node_failed` | WARNING | 节点失败 |
| `agentflow_run_completed` | INFO | run 完成 |
| `agentflow_run_cancelled` | WARNING | 用户取消 |
| `agentflow_run_timeout` | ERROR | run 整体超时 |
| `agentflow_token_summary` | INFO | token 聚合完成 |
| `agentflow_run_cleaned` | INFO | 过期 run 目录被清理 |

---

## 6. 告警规则建议（Phase 3 配合 Prometheus）

| 告警名 | 条件 | 严重度 |
|---|---|---|
| `FwUnpackHighFailureRate` | 5min 内失败率 > 30% | P1 |
| `FwUnpackTaskStuck` | 任务运行 > 2h 仍为 RUNNING | P2 |
| `FwUnpackNodeTimeout` | 节点运行 > 配置 timeout 的 1.5x | P2 |
| `FwUnpackTokenSpike` | 1h 内 token 消耗 > 日均 3x | P2 |
| `FwUnpackRunsDiskFull` | runs 目录 > 80% 磁盘配额 | P3 |
| `FwUnpackWorkerDown` | Worker 心跳超时 > dead_threshold | P2 |

---

## 7. 实施优先级与依赖

```
Phase 1 (灰度前)
  ├── [G1] Token 聚合        ← 1 天，agentflow_runner.py
  ├── [G2] 节点耗时 API      ← 0.5 天，firmware.py
  └── [G3] Trace 桥接日志    ← 1 天，agentflow_runner.py

Phase 2 (灰度期间)
  ├── [G5] AgentFlow API 增强 ← 0.5 天，firmware.py
  ├── [G6] 集群 AF 指标       ← 0.5 天，worker.py + firmware.py
  ├── [G7] Run 清理实现       ← 0.5 天，worker.py
  └── [G8] 取消事件记录       ← 0.5 天，agentflow_runner.py

Phase 3 (生产稳定后)
  ├── [G9] Prometheus metrics ← 2 天，新增 app/metrics.py + 依赖
  ├── [G9+] OTel trace        ← 1 天，按需
  └── [G11] SSE 实时推送      ← 2 天，按需
```

---

## 8. 风险

| 风险 | 影响 | 应对 |
|---|---|---|
| Trace 文件格式不稳定 | Token 聚合解析失败 | 做好 fallback，解析失败记录 warning 日志，不阻塞主流程 |
| events.jsonl 延迟写入 | Trace 桥接遗漏事件 | 最终再桥接一次；日志中标注 `final_bridge=true` |
| Prometheus 依赖引入 | 镜像体积/依赖冲突 | Phase 3 再引入；Phase 1/2 仅用日志和文件 |
| Run 目录清理误删 | 丢失排查数据 | 保留天数 ≥ 7；删除前记录日志；可配置 `retention_days=0` 禁用 |

---

## 9. 验收标准

### Phase 1 验收

- [ ] `tokens_summary.json` 包含非零 `total_prompt_tokens` 和 `total_completion_tokens`（对真实 pi 运行）
- [ ] `/agentflow` API 返回每个节点的 `duration_seconds`
- [ ] 应用日志中可搜索 `agentflow_node_event` 和 `agentflow_run_completed`
- [ ] 失败任务的日志包含失败节点 ID 和错误信息

### Phase 2 验收

- [ ] `/agentflow` API 返回 `failed_nodes` 和 `token_summary`
- [ ] `/cluster` API 返回 `agentflow_active_runs`
- [ ] 超过 `cleanup_runs_retention_days` 的 run 目录被自动清理
- [ ] 取消任务日志包含 `current_nodes` 快照

### Phase 3 验收

- [ ] `/metrics` 端点可被 Prometheus 抓取
- [ ] Grafana 可展示任务成功率、耗时分布、token 消耗趋势
- [ ] AlertManager 可触发上述告警规则