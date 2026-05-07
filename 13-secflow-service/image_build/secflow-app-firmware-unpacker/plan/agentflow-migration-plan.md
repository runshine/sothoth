# SecFlow Firmware Unpacker AgentFlow 迁移计划

编写日期：2026-05-07

## 1. 背景与目标

当前 `secflow-app-firmware-unpacker` 是一个 FastAPI 微服务，外层已经具备任务提交、任务排队、Worker 注册、心跳、并发控制、取消、重试、任务清理、Kubernetes 部署等能力。真正需要迁移的是固件解包执行链路：当前由 `app/unpacker_engine.py` 中的 `PiRpcClient` 手写串行调用多个 pi agent，流程状态和日志也由业务代码自行拼装。

迁移目标不是把整个微服务替换成 AgentFlow，而是保留现有服务外壳，将固件解包引擎改造成 AgentFlow pipeline：

- API、数据库模型、Worker 调度、Kubernetes Service/Deployment 继续沿用现有实现。
- `task_manager` 仍负责从 DB 领取任务，并调用 `run_unpack()`。
- `run_unpack()` 变成兼容入口，根据配置选择 legacy engine 或 AgentFlow engine。
- AgentFlow 负责编排预处理、技能匹配、技能执行、通用 agent 解包、评审循环、技能沉淀、清理和汇总。
- 迁移过程支持灰度开关和回滚，不影响现有 API 调用方。

## 2. 当前架构梳理

### 2.1 任务入口

- `app/api/firmware.py`：提供任务提交、列表、详情、取消、重试、删除、配置、工具列表等接口。
- `app/services/task_manager.py`：
  - `submit_unpack_task()` 创建 DB 任务和任务工作目录。
  - `_schedule_pending_tasks()` 从 DB 中领取 pending 任务。
  - `_run_claimed_task()` 在线程池中运行任务。
  - `_update_task_result()` 将 `run_unpack()` 返回值写回 DB。
- `app/services/worker.py`：负责 Worker 注册、心跳、孤儿任务回收、历史任务清理和集群快照。

### 2.2 解包引擎入口

当前核心入口为：

- `app/unpacker_engine.py::run_unpack(firmware_path, output_path, cancel_check=None)`

当前执行流程大致为：

1. 创建输出目录和运行日志目录。
2. `run_preprocess()` 尝试快速预处理。
3. `extract_firmware_features()` 提取固件特征。
4. `match_skill()` 匹配历史固件解包 skill。
5. 如果命中 skill：
   - 使用 skill system prompt 启动 pi executor。
   - 调用 reviewer 校验输出。
   - 成功则登记 skill 成功次数。
   - 失败则 fallback 到通用 LLM 解包。
6. 通用解包：
   - executor 执行。
   - reviewer 校验。
   - 未通过则进入下一轮重试，直到 `max_retries`。
7. 成功后调用 skill author 生成候选 skill。
8. 调用 cleaner 清理输出。
9. 写 token summary 和阶段日志。
10. 返回与 DB 写入兼容的 result dict。

### 2.3 当前痛点

- agent 调用由 `PiRpcClient` 手写管理，进程生命周期、重试、日志、取消都耦合在业务代码中。
- 执行流程是串行 Python 逻辑，不容易观察每个阶段的状态、耗时、输出和失败原因。
- 通用解包和评审循环由 for-loop 实现，难以扩展成更复杂的 DAG。
- 后续如果要引入多个 agent 并行评审、批量候选策略、远程执行、图优化，现有结构需要继续堆业务代码。
- AgentFlow 已在仓库中存在，但当前 Docker 镜像和服务代码尚未安装或调用它。

## 3. 目标架构

迁移后的运行链路：

```text
FastAPI API
  -> DB pending task
  -> task_manager worker thread
  -> run_unpack()
  -> run_unpack_agentflow()
  -> AgentFlow Orchestrator
  -> AgentFlow pipeline nodes
  -> result adapter
  -> _update_task_result()
```

建议保留 legacy 链路：

```text
run_unpack()
  -> if UNPACKER_ENGINE_MODE=legacy: run_unpack_legacy()
  -> if UNPACKER_ENGINE_MODE=agentflow: run_unpack_agentflow()
```

这样可以做到：

- 开发阶段默认 legacy。
- 单任务或单环境灰度 agentflow。
- AgentFlow 失败时可配置 fallback 到 legacy。
- 若线上出现问题，只需修改配置回滚。

## 4. AgentFlow Pipeline 设计

### 4.1 节点划分

建议第一版 AgentFlow pipeline 拆成如下节点：

| 节点 ID | 类型 | 作用 | 输入 | 输出 |
|---|---|---|---|---|
| `preprocess` | `python_node` | 调用 `run_preprocess()` 快速解包 | firmware path, output path | success, method |
| `feature_match` | `python_node` | 提取固件特征并匹配 skill | firmware path, tools dir | features, matched_skill |
| `skill_executor` | `pi` | 使用命中的 skill 执行解包 | skill prompt, firmware path, output path | executor output |
| `skill_reviewer` | `pi` | 校验 skill 解包结果 | firmware path, output path | review JSON/text |
| `generic_executor` | `pi` | 通用固件解包 agent | firmware path, output path, last review | executor output |
| `generic_reviewer` | `pi` | 校验通用解包结果 | firmware path, output path | review JSON/text |
| `skill_author` | `pi` | 成功后生成候选 skill | features, summary, review | skill markdown |
| `cleanup` | `pi` | 清理和规范化输出目录 | output path | cleanup output |
| `finalize` | `python_node` | 汇总各节点输出为现有 result dict | all node outputs | final result |

### 4.2 第一版图结构

第一版以稳定迁移为目标，暂不做复杂并行：

```text
preprocess
  -> feature_match
  -> skill_executor
  -> skill_reviewer
  -> generic_executor
  -> generic_reviewer
  -> skill_author
  -> cleanup
  -> finalize
```

注意：AgentFlow 当前 DSL 更适合静态 DAG。对于“如果 preprocess 成功则跳过后续 agent”“如果 skill 命中才执行 skill_executor”“如果 skill 评审成功则跳过 generic”的条件分支，建议第一阶段用节点内部逻辑和 `finalize` 适配，不要一开始强行追求完美条件 DAG。

落地策略：

- `preprocess` 写出 `preprocess.json`。
- 后续节点启动时读取前序结果，如果已经成功则直接输出 `SKIPPED_BY_PREPROCESS`。
- `feature_match` 未命中 skill 时，`skill_executor` 输出 `SKIPPED_NO_SKILL`。
- `skill_reviewer` 发现 `skill_executor` skipped 时也 skipped。
- `generic_executor` 只有在 preprocess 未成功且 skill 未验证成功时真正执行。
- `finalize` 根据节点输出决定最终 `status/message/rounds/matched_skill/...`。

### 4.3 通用解包重试循环

当前 `run_unpack()` 中的重试逻辑：

```text
for attempt in 1..max_retries:
  executor
  reviewer
  if reviewer success:
    break
```

AgentFlow 推荐方式：

```python
generic_executor >> generic_reviewer
generic_reviewer.on_failure >> generic_executor
generic_reviewer >> skill_author
```

`generic_reviewer` 应设置成功条件：

- reviewer 输出包含 `"result":"success"` 或 `"result": "success"`。
- 第一版也可以要求 reviewer 成功时输出固定标记，例如 `AGENTFLOW_REVIEW_SUCCESS`，降低解析风险。

实现建议：

- `Graph(max_iterations=max_retries)` 使用运行时配置中的 `max_retries`。
- `generic_executor` prompt 中使用 Jinja2 读取上一轮 reviewer 输出：
  - 首轮使用 `unpack-firmware.md`。
  - 后续轮次使用 `retry-firmware-unpack.md` 语义，并注入 `nodes.generic_reviewer.output`。
- 若 AgentFlow 的 success criteria 无法完全表达 JSON 判断，先让 reviewer prompt 明确要求成功时包含固定字符串。

### 4.4 是否使用 fanout

第一阶段不建议使用 fanout。原因：

- 固件解包对同一个输出目录有写冲突风险。
- 当前业务语义是单 executor 修改同一个 output path。
- 并行多个 executor 会引入结果合并和覆盖问题。

第二阶段可以考虑 fanout：

- 多 reviewer 并行评审同一 output。
- 多个只读分析 agent 并行识别固件类型。
- 多个候选策略写入不同临时 output 目录，最后由 merge 节点选择最佳结果。

## 5. 代码改造计划

### 阶段 0：准备与基线

目标：保证迁移前有明确基线和可回归路径。

任务：

- 记录当前 legacy 路径的关键行为：
  - preprocess 成功返回字段。
  - skill 命中成功返回字段。
  - skill 失败 fallback 返回字段。
  - max retries 返回字段。
  - cancel 返回字段。
- 给 `run_unpack()` 增加最小覆盖测试，至少验证返回 dict 字段兼容。
- 准备一个小固件样本或 mock 样本，用于 smoke test。

验收：

- `pytest` 当前测试通过。
- legacy engine 行为有测试或手工记录。
- 明确可回滚配置：`UNPACKER_ENGINE_MODE=legacy`。

### 阶段 1：安装并验证 AgentFlow 运行时

目标：让服务镜像内可以 import 和运行 AgentFlow。

改动文件：

- `Dockerfile`
- `requirements.txt`
- 可能新增 `scripts/check_agentflow_runtime.py`

建议改动：

- Dockerfile 增加：

```dockerfile
COPY agentflow/ /app/agentflow/
RUN pip3 install --no-cache-dir -e /app/agentflow
```

- 如果 AgentFlow 缺少运行依赖，则补充到构建层中。
- 保留现有 `pi-coding-agent` 安装，AgentFlow 的 `pi` adapter 会调用 `pi` 命令。
- 增加镜像内健康校验：

```bash
python -c "import agentflow; print(agentflow.__file__)"
pi --version
```

验收：

- 本地或 CI 能构建镜像。
- 容器内 `import agentflow` 成功。
- 容器内 `pi` 命令可用。

### 阶段 2：新增 AgentFlow 配置

目标：通过配置控制引擎模式、run 目录、并发和 fallback。

改动文件：

- `app/config.py`
- `config.yaml`
- `k8s-configmap.yaml`
- 平台总装 ConfigMap 文件

新增配置建议：

```yaml
agentflow:
  enabled: false
  engine_mode: "legacy"       # legacy | agentflow
  fallback_to_legacy: true
  runs_dir: "/data/files/.agentflow/runs"
  max_concurrent_runs: 2
  node_timeout_seconds: 1800
  use_worktree: false
  cleanup_runs_retention_days: 7
```

环境变量覆盖建议：

- `UNPACKER_ENGINE_MODE`
- `AGENTFLOW_RUNS_DIR`
- `AGENTFLOW_MAX_CONCURRENT_RUNS`
- `AGENTFLOW_FALLBACK_TO_LEGACY`

验收：

- 服务启动时打印当前 engine mode。
- 默认行为仍为 legacy。
- 配置缺失时不影响现有部署。

### 阶段 3：抽出 legacy engine

目标：为双轨运行做代码结构准备。

改动文件：

- `app/unpacker_engine.py`
- 新增 `app/unpacker_legacy_engine.py` 或在原文件内先保留 `run_unpack_legacy()`

建议改动：

- 将当前 `run_unpack()` 主体重命名为 `run_unpack_legacy()`。
- 新的 `run_unpack()` 只负责选择 engine：

```python
def run_unpack(firmware_path: str, output_path: str, cancel_check=None) -> dict:
    mode = get_unpack_engine_mode()
    if mode == "agentflow":
        try:
            return run_unpack_agentflow(firmware_path, output_path, cancel_check=cancel_check)
        except Exception:
            if agentflow_fallback_enabled():
                log.exception("agentflow engine failed, falling back to legacy")
                return run_unpack_legacy(firmware_path, output_path, cancel_check=cancel_check)
            raise
    return run_unpack_legacy(firmware_path, output_path, cancel_check=cancel_check)
```

验收：

- 默认 legacy 路径行为不变。
- 原有测试不需要大规模修改。
- `task_manager` 调用点无需改变。

### 阶段 4：新增 AgentFlow pipeline builder

目标：用代码生成固件解包 AgentFlow 图。

新增文件：

- `app/agentflow_pipeline.py`

核心职责：

- 加载现有 agent definition。
- 渲染现有 prompt template。
- 构造 `Graph`。
- 设置 `working_dir`、`concurrency`、`max_iterations`。
- 为每个 `pi` 节点设置 model、tools、system prompt extra args。

注意事项：

- 当前 AgentFlow `pi` adapter 支持 `extra_args`，可传入：

```python
extra_args=["--append-system-prompt", "/tmp/firmware-unpacker.md"]
```

- `tools` 需要从现有 frontmatter 映射：
  - 包含写入/编辑/bash 能力：`read_write`
  - 只读评审：`read_only` 或按 reviewer 实际需要设 `read_write`
- 所有节点 prompt 应尽量复用 `app/agent/prompt/*.md`，避免迁移时改 prompt 语义。

示例骨架：

```python
from agentflow import Graph, pi, python_node

def build_firmware_unpack_pipeline(ctx: dict):
    with Graph(
        "firmware-unpack",
        working_dir=ctx["base_dir"],
        concurrency=ctx["agentflow_concurrency"],
        max_iterations=ctx["max_retries"],
        use_worktree=False,
    ) as g:
        preprocess = python_node(
            task_id="preprocess",
            code=render_preprocess_code(ctx),
        )

        feature_match = python_node(
            task_id="feature_match",
            code=render_feature_match_code(ctx),
        )

        generic_executor = pi(
            task_id="generic_executor",
            prompt=render_generic_executor_prompt(ctx),
            tools="read_write",
            model=ctx["exec_model"],
            extra_args=["--append-system-prompt", ctx["exec_system_prompt_path"]],
        )

        generic_reviewer = pi(
            task_id="generic_reviewer",
            prompt=render_reviewer_prompt(ctx),
            tools="read_write",
            model=ctx["review_model"],
            extra_args=["--append-system-prompt", ctx["review_system_prompt_path"]],
            success_criteria=[
                {"kind": "output_contains", "value": "AGENTFLOW_REVIEW_SUCCESS"}
            ],
        )

        preprocess >> feature_match >> generic_executor >> generic_reviewer
        generic_reviewer.on_failure >> generic_executor

    return g.to_spec()
```

验收：

- 单测可构造 pipeline。
- `PipelineSpec.model_validate()` 通过。
- 生成 JSON 中包含预期节点和依赖。

### 阶段 5：新增 AgentFlow runner

目标：在服务进程内运行 AgentFlow pipeline，并把结果转换成现有 result dict。

新增文件：

- `app/agentflow_runner.py`

核心职责：

- 创建 `RunStore`。
- 创建 `Orchestrator`。
- 提交 pipeline。
- 等待 run 完成。
- 支持取消。
- 读取 node outputs 和 traces。
- 转换为 `_update_task_result()` 可消费的 dict。

建议接口：

```python
def run_unpack_agentflow(
    firmware_path: str,
    output_path: str,
    cancel_check=None,
    task_id: str | None = None,
    project_id: str | None = None,
) -> dict:
    ...
```

取消处理建议：

- `run_unpack_agentflow()` 等待期间周期性调用 `cancel_check()`。
- 一旦发现取消，调用 `orchestrator.cancel(run_id)`。
- 返回：

```python
{
    "status": "cancelled",
    "message": "Task was cancelled",
    "rounds": current_round,
}
```

运行目录建议：

```text
<task_base_dir>/run/
  agentflow_run_id.txt
  agentflow/
    runs/<run_id>/
  stage2_skill_match.json
  tokens_summary.json
  final_result.json
```

验收：

- mock pipeline 能在服务内运行。
- 成功/失败/取消均能转换成现有 result dict。
- `task_manager._update_task_result()` 不需要改或只做少量字段增强。

### 阶段 6：迁移最小可用图

目标：先跑通 AgentFlow 最小链路，不迁移 skill 逻辑。

最小链路：

```text
preprocess -> generic_executor -> generic_reviewer -> cleanup -> finalize
```

策略：

- preprocess 成功时，后续 agent 节点快速 skipped。
- generic executor/reviewer 复用现有 `firmware-unpacker.md` 和 `firmware-unpack-reviewer.md`。
- cleanup 复用现有 `firmware-extract-cleanup.md`。
- finalize 输出当前兼容字段。

验收：

- `UNPACKER_ENGINE_MODE=agentflow` 时，任务可完成。
- 输出目录结构与 legacy 基本一致。
- DB 中 `status/result_status/result_message/rounds` 正确。
- 失败任务能看到 AgentFlow run 目录和 node 输出。

### 阶段 7：迁移 skill 匹配和 skill 执行

目标：恢复现有 fast mode 和 skill 复用能力。

新增/调整节点：

```text
feature_match -> skill_executor -> skill_reviewer
```

业务规则：

- `feature_match` 调用 `extract_firmware_features()`、`compute_family_id()`、`match_skill()`。
- 命中 skill 时，`skill_executor` 使用 skill 中的 system prompt。
- `skill_reviewer` 复用 reviewer agent 校验输出。
- skill 成功时，调用 `register_skill_success()`。
- skill 失败时，generic executor 继续执行。

验收：

- 命中 skill 且 review 成功时，不再执行 generic 解包。
- skill 成功后 promotion count 正确增加。
- skill 失败时 fallback 到 generic。
- `matched_skill/matched_skill_version/matched_skill_score/fallback_to_llm` 字段与 legacy 兼容。

### 阶段 8：迁移 skill author

目标：恢复成功解包后的候选 skill 生成能力。

新增节点：

```text
skill_author
```

规则：

- 仅当最终解包成功且不是 preprocess 直接成功时执行。
- 输入包括：
  - firmware features
  - output summary
  - reviewer 成功结果
  - family id
  - promotion threshold
- 调用 `save_candidate_skill()` 保存候选 skill。
- 写出 `stage5_skill_generate.json`。

验收：

- 成功解包后生成候选 skill。
- DB 中 `generated_skill_path/generated_skill_status/promotion_success_count` 正确。
- 生成失败不影响主任务成功。

### 阶段 9：日志、可观测性和管理接口增强

目标：让 AgentFlow 运行结果能被 API 和运维定位。

建议增强：

- DB 增加字段：
  - `agentflow_run_id`
  - `engine_mode`
  - `engine_error`
- `TaskResponse` 增加：
  - `agentflow_run_id`
  - `run_path`
  - `engine_mode`
- 任务详情接口可返回 AgentFlow run id。
- 可选新增接口：
  - `GET /api/app/firmware-unpacker/tasks/{task_id}/agentflow`
  - 返回 run 状态、节点列表、失败节点、trace 路径。

验收：

- 线上可以通过 task id 定位 AgentFlow run。
- 失败节点的 output 和 error 可查。
- 旧客户端不受新增字段影响。

### 阶段 10：生产灰度与切换

目标：安全切换默认 engine。

建议流程：

1. 部署包含 AgentFlow 的镜像，但配置仍为 legacy。
2. 在测试环境开启 `UNPACKER_ENGINE_MODE=agentflow`。
3. 跑固定样本集，对比 legacy 与 agentflow：
   - 成功率。
   - 平均耗时。
   - token 消耗。
   - 输出目录完整性。
   - reviewer 通过率。
4. 在生产中按单 Pod 或单命名空间灰度。
5. 观察任务失败率和资源使用。
6. 默认切换到 agentflow。
7. 保留 legacy fallback 至少一个版本周期。

验收：

- AgentFlow 默认启用后，任务成功率不低于 legacy。
- 平均耗时和资源占用在可接受范围内。
- 回滚只需要改配置，不需要重新构建镜像。

## 6. 文件级改动清单

### 必改

- `Dockerfile`
  - 拷贝并安装 `agentflow/`。
  - 确认容器内 `agentflow` 和 `pi` 均可用。

- `requirements.txt`
  - 补充 AgentFlow 运行依赖，或依赖 `pip install -e /app/agentflow` 自动解析。

- `app/config.py`
  - 增加 `AgentFlowConfig`。
  - 支持 env override。

- `config.yaml`
  - 增加 `agentflow` 配置段。

- `app/unpacker_engine.py`
  - 抽出 `run_unpack_legacy()`。
  - 新 `run_unpack()` 根据配置分发。

- `app/agentflow_pipeline.py`
  - 新增 pipeline 构建逻辑。

- `app/agentflow_runner.py`
  - 新增运行、等待、取消、结果适配逻辑。

### 建议改

- `app/model.py`
  - 增加 `agentflow_run_id`、`engine_mode` 等字段。

- `app/schemas.py`
  - 在任务响应中暴露 engine/run 信息。

- `app/api/firmware.py`
  - 可选新增 AgentFlow run 状态接口。

- `app/services/task_manager.py`
  - 可选将 `task_id/project_id` 传入 `run_unpack()`，便于 runner 保存 run 映射。

- `README.md`
  - 补充 AgentFlow engine 配置和运行说明。

- `k8s-configmap.yaml`
  - 增加 agentflow 配置。

- `k8s-deployment.yaml`
  - 增加 AgentFlow runs 目录挂载或环境变量。

## 7. 兼容性要求

### 7.1 API 兼容

不能破坏以下接口：

- `POST /api/app/firmware-unpacker/projects/{project_id}/tasks`
- `GET /api/app/firmware-unpacker/projects/{project_id}/tasks`
- `GET /api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}`
- `DELETE /api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}`
- 旧版 `/unpack`、`/tasks` 系列接口。

新增字段必须是向后兼容的 optional 字段。

### 7.2 Result dict 兼容

AgentFlow engine 最终必须返回当前 `_update_task_result()` 可处理的字段：

```python
{
    "status": "success" | "max_retries_reached" | "cancelled" | "failed",
    "message": "...",
    "rounds": 0,
    "matched_skill": "...",
    "matched_skill_version": 1,
    "matched_skill_score": 0,
    "fallback_to_llm": False,
    "generated_skill_path": "...",
    "generated_skill_status": "...",
    "promotion_success_count": 0,
}
```

### 7.3 输出目录兼容

必须继续使用当前任务目录：

```text
/data/files/<project_id>/app/secflow-app-firmware-unpacker/<task_id>/
  input/
  output/
  run/
```

AgentFlow traces 可以放在 `run/agentflow/` 下，不能污染 `output/`。

## 8. 取消与超时设计

当前取消机制：

- API 将任务状态改为 `CANCELLING`。
- `task_manager` 通过 `cancel_check()` 让 `run_unpack()` 感知取消。
- legacy engine 关闭当前 `PiRpcClient`。

AgentFlow 迁移后：

- `run_unpack_agentflow()` 等待 run 时每 1-2 秒检查一次 `cancel_check()`。
- 如果需要取消：
  - 调用 `orchestrator.cancel(run_id)`。
  - 等待短时间让节点退出。
  - 返回 `status=cancelled`。
- 如果 AgentFlow 节点无法及时退出：
  - 标记任务 cancelled。
  - 在日志中记录 orphan AgentFlow run。
  - 后续由 AgentFlow run cleanup 清理。

节点超时：

- 每个 pi 节点应设置 `timeout_seconds`。
- 默认建议 1800 秒。
- reviewer 可短一些，例如 900 秒。
- cleanup 可短一些，例如 600 秒。

## 9. 日志与追踪设计

保留现有阶段日志文件名，降低 UI 或运维认知成本：

- `stage2_skill_match.json`
- `stage3_skill_exec.json`
- `stage4_llm_fallback.json`
- `stage5_skill_generate.json`
- `tokens_summary.json`

新增 AgentFlow 原生日志：

```text
run/
  agentflow_run_id.txt
  agentflow/
    runs/<run_id>/
      run.json
      events.jsonl
      nodes/
      traces/
```

最终汇总：

```text
run/final_result.json
```

## 10. 风险与应对

### 风险 1：AgentFlow 静态 DAG 不完全匹配现有条件分支

应对：

- 第一阶段用节点内部 skipped 逻辑实现条件跳过。
- 稳定后再考虑扩展 AgentFlow 的条件节点能力。

### 风险 2：pi system prompt 传递方式差异

应对：

- 优先使用 `extra_args=["--append-system-prompt", path]`。
- 如果行为不一致，再扩展 AgentFlow `PiAdapter` 增加 `system_prompt_file` 字段。

### 风险 3：输出目录写冲突

应对：

- 第一阶段不使用 executor fanout。
- `use_worktree=False`，保持对当前任务目录的直接写入。
- 如果后续并行候选解包，必须每个 candidate 使用独立 output 子目录。

### 风险 4：取消不及时

应对：

- 设置节点 timeout。
- `run_unpack_agentflow()` 主动 cancel AgentFlow run。
- 记录 run id，支持后台排查和清理。

### 风险 5：镜像体积和依赖冲突

应对：

- AgentFlow 以 editable install 方式先接入。
- 构建时固定依赖版本。
- 如果依赖冲突，将 AgentFlow 运行时隔离到单独 venv 或子进程。

### 风险 6：线上失败率升高

应对：

- 默认 legacy。
- 支持 `fallback_to_legacy=true`。
- 分环境、分 Pod 灰度。
- 至少保留一个版本周期的 legacy fallback。

## 11. 测试计划

### 单元测试

- pipeline 构造测试：
  - 节点 ID 完整。
  - 依赖关系正确。
  - `PipelineSpec` 校验通过。
- result adapter 测试：
  - preprocess success。
  - skill success。
  - skill failed fallback generic success。
  - max retries reached。
  - cancelled。
- config 测试：
  - 默认 legacy。
  - env override 生效。

### 集成测试

- 容器内 smoke：

```bash
python -c "import agentflow"
pi --version
```

- 服务级 smoke：

```bash
POST /api/app/firmware-unpacker/projects/{project_id}/tasks
GET  /api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}
```

- AgentFlow run 检查：
  - run id 已写入 run 目录。
  - node outputs 可查。
  - final_result.json 存在。

### 回归测试

- legacy mode 下原有测试全部通过。
- agentflow mode 下核心任务测试通过。
- fallback 开启时，模拟 AgentFlow 抛错后任务仍可由 legacy 完成。

## 12. 里程碑

### M1：运行时接入

交付物：

- Docker 镜像内 AgentFlow 可 import。
- 配置中存在 agentflow 段。
- 默认 legacy 不变。

### M2：双轨入口

交付物：

- `run_unpack_legacy()` 保留原行为。
- `run_unpack()` 支持 engine mode 分发。
- fallback 可配置。

### M3：最小 AgentFlow 解包链路

交付物：

- `preprocess -> generic_executor -> reviewer -> cleanup -> finalize` 跑通。
- DB 状态正确。
- AgentFlow run 日志可查。

### M4：完整 skill 链路

交付物：

- skill match、skill executor、skill reviewer、promotion count 迁移完成。
- skill fallback generic 正常。

### M5：skill author 与观测完善

交付物：

- candidate skill 生成迁移完成。
- run id、engine mode、节点状态可观测。

### M6：灰度上线

交付物：

- 测试环境默认 agentflow。
- 生产灰度完成。
- 默认 engine 可切到 agentflow。

## 13. 建议实施顺序

建议严格按以下顺序实施：

1. 新增配置和 Docker AgentFlow 安装。
2. 抽出 legacy，保持默认行为不变。
3. 新增 AgentFlow runner 和 pipeline builder。
4. 跑通最小 AgentFlow pipeline。
5. 接入 engine mode 灰度开关。
6. 迁移 skill match 和 skill executor。
7. 迁移 skill author。
8. 增加 run id 可观测字段和接口。
9. 测试环境启用 agentflow。
10. 生产灰度。

## 14. 回滚方案

最快回滚：

```yaml
agentflow:
  engine_mode: "legacy"
```

或环境变量：

```bash
UNPACKER_ENGINE_MODE=legacy
```

如果 AgentFlow 安装导致镜像启动失败：

- 回滚到上一版镜像。
- 或临时构建不包含 AgentFlow 安装层的镜像。

如果单个任务失败：

- 开启 `fallback_to_legacy=true`。
- AgentFlow 抛错后自动进入 legacy。
- DB 中保留失败前的 AgentFlow run id 供排查。

## 15. 后续增强方向

迁移稳定后可以继续利用 AgentFlow 能力：

- 多 reviewer fanout，降低误判。
- 多策略 candidate output，并行尝试不同解包路线。
- merge 节点选择最佳输出。
- 使用远程 EC2/ECS target 执行高资源消耗解包。
- 使用 scratchboard 保存跨节点分析结论。
- 为常见固件族构建 tuned agent。
- 将 AgentFlow web UI 暴露为内部调试页面。

