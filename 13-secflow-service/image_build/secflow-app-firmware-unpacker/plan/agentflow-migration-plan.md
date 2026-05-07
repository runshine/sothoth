# SecFlow Firmware Unpacker AgentFlow 迁移计划

编写日期：2026-05-07
更新日期：2026-05-07

## 0. 当前进度摘要

当前迁移已经完成主干代码接入，整体进度约 75%-85%。服务只保留 AgentFlow 解包模式；代码层面已具备 AgentFlow 入口、pipeline builder、runner、DB/API 可观测字段和基础测试。剩余重点是补齐 AgentFlow runner 的 mock 测试、容器内真实运行 smoke test、固定固件样本验证和生产切换。

状态标记：

- `[DONE]`：代码已落地，并有基础测试或静态检查支撑。
- `[PARTIAL]`：代码已落地，但真实运行、边界行为或验收证据不足。
- `[TODO]`：尚未落地或尚未执行。

阶段完成度：

| 阶段 | 状态 | 当前说明 |
|---|---|---|
| 阶段 0：准备与基线 | `[PARTIAL]` | AgentFlow 配置和入口有测试；skill 成功、skill fallback、max retry、cancel 的结果形状还缺少覆盖。 |
| 阶段 1：安装并验证 AgentFlow 运行时 | `[DONE]` | `Dockerfile` 已复制并 editable install `agentflow/`，构建层包含 `import agentflow` 和 `pi --version` 校验。 |
| 阶段 2：新增 AgentFlow 配置 | `[DONE]` | `app/config.py`、`config.yaml`、`k8s-configmap.yaml` 已加入 `agentflow` 配置和环境变量覆盖。 |
| 阶段 3：AgentFlow 单入口 | `[DONE]` | `run_unpack()` 已固定调用 `run_unpack_agentflow()`，不再保留运行时引擎切换。 |
| 阶段 4：新增 AgentFlow pipeline builder | `[DONE]` | `app/agentflow_pipeline.py` 已生成完整节点图，单测覆盖节点和依赖关系。 |
| 阶段 5：新增 AgentFlow runner | `[PARTIAL]` | `app/agentflow_runner.py` 已实现提交、等待、取消、结果适配；缺少成功/失败/取消的 mock runner 单测和真实 run 验证。 |
| 阶段 6：迁移最小可用图 | `[PARTIAL]` | 图中已包含 preprocess、generic executor/reviewer、cleanup、finalize；尚未跑通真实 AgentFlow 样本任务。 |
| 阶段 7：迁移 skill 匹配和 skill 执行 | `[PARTIAL]` | `feature_match`、`skill_executor`、`skill_reviewer`、promotion count 逻辑已接入；尚缺命中 skill 的集成验证。 |
| 阶段 8：迁移 skill author | `[PARTIAL]` | `skill_author` 节点和 `save_candidate_skill()` 适配已接入；尚缺成功生成候选 skill 的集成验证。 |
| 阶段 9：日志、可观测性和管理接口增强 | `[DONE]` | DB、schema、任务详情、AgentFlow run 状态接口已加入；token summary 目前仍是占位。 |
| 阶段 10：生产灰度与切换 | `[TODO]` | 尚未看到测试环境默认 agentflow、样本集对比或生产灰度记录。 |

当前测试结果：

```text
pytest -q
12 passed in 0.21s
```

下一轮最小验收目标：

1. 为 `run_unpack_agentflow()` 增加 mock Orchestrator/RunStore 单测，覆盖 success、failed、cancelled。
2. 构建或进入镜像，确认 `python -c "import agentflow"` 和 `pi --version` 在容器内通过。
3. 使用一个小 zip 固件样本跑服务级 smoke，确认 DB、`run/final_result.json`、`run/agentflow/runs/<run_id>/run.json` 均正确。
4. 补一条命中 skill 的样本或 mock，验证 skill success 时不执行 generic，skill failed 时 fallback generic。
5. 测试环境灰度开启 agentflow，收集成功率、耗时、输出目录完整性和 reviewer 通过率。

## 1. 背景与目标

当前 `secflow-app-firmware-unpacker` 是一个 FastAPI 微服务，外层已经具备任务提交、任务排队、Worker 注册、心跳、并发控制、取消、重试、任务清理、Kubernetes 部署等能力。真正需要迁移的是固件解包执行链路：当前由 `app/unpacker_engine.py` 中的 `PiRpcClient` 手写串行调用多个 pi agent，流程状态和日志也由业务代码自行拼装。

迁移目标不是把整个微服务替换成 AgentFlow，而是保留现有服务外壳，将固件解包引擎改造成 AgentFlow pipeline：

- API、数据库模型、Worker 调度、Kubernetes Service/Deployment 继续沿用现有实现。
- `task_manager` 仍负责从 DB 领取任务，并调用 `run_unpack()`。
- `run_unpack()` 固定为 AgentFlow 入口。
- AgentFlow 负责编排预处理、技能匹配、技能执行、通用 agent 解包、评审循环、技能沉淀、清理和汇总。
- 迁移过程不再保留旧运行时路径，不影响现有 API 调用方。

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
- AgentFlow 已在仓库中存在，并已接入 Docker 镜像和服务代码；当前剩余风险主要是真实 AgentFlow/pi 链路和灰度运行尚未完成验收。

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

当前固定链路：

```text
run_unpack()
  -> run_unpack_agentflow()
```

这样可以做到：

- 服务代码只有一个执行入口，减少分支和状态字段。
- API、DB 任务状态和输出目录仍保持兼容。
- 若线上出现问题，通过修复 AgentFlow 链路或回滚镜像处理。

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

### 阶段 0：准备与基线 `[PARTIAL]`

目标：保证迁移前有明确基线和可回归路径。

任务：

- 记录 AgentFlow result adapter 的关键行为：
  - preprocess 成功返回字段。
  - skill 命中成功返回字段。
  - skill 失败 fallback 返回字段。
  - max retries 返回字段。
  - cancel 返回字段。
- 给 `run_unpack()` 和 `run_unpack_agentflow()` 增加覆盖测试，至少验证返回 dict 字段兼容。
- 准备一个小固件样本或 mock 样本，用于 smoke test。

验收：

- `pytest` 当前测试通过。
- AgentFlow result adapter 行为有测试或手工记录。
- 明确镜像级回滚方案。

当前状态：

- 已有 `tests/test_agentflow_migration.py` 覆盖默认 AgentFlow、env override、pipeline 构造、`run_unpack()` 调用 AgentFlow。
- 尚需补充 AgentFlow skill success、skill fallback、max retries、cancel 的结果形状测试或手工记录。
- 小 zip 固件样本已在测试中用于 preprocess success；服务级 AgentFlow smoke 样本尚未执行。

### 阶段 1：安装并验证 AgentFlow 运行时 `[DONE]`

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

当前状态：

- `Dockerfile` 已复制 `agentflow/` 并执行 `pip3 install --no-cache-dir -e /app/agentflow`。
- 构建层已加入 `python3 -c "import agentflow; print(agentflow.__file__)"` 和 `pi --version`。
- 仍建议在目标 CI 或实际构建节点保留一次完整镜像构建记录。

### 阶段 2：新增 AgentFlow 配置 `[DONE]`

目标：通过配置控制 run 目录、并发和节点超时。

改动文件：

- `app/config.py`
- `config.yaml`
- `k8s-configmap.yaml`
- 平台总装 ConfigMap 文件

新增配置建议：

```yaml
agentflow:
  enabled: true
  runs_dir: "/data/files/.agentflow/runs"
  max_concurrent_runs: 2
  node_timeout_seconds: 1800
  use_worktree: false
  cleanup_runs_retention_days: 7
```

环境变量覆盖建议：

- `AGENTFLOW_RUNS_DIR`
- `AGENTFLOW_MAX_CONCURRENT_RUNS`

验收：

- 服务启动时打印 AgentFlow enabled 状态。
- 默认行为为 AgentFlow。
- 配置缺失时不影响现有部署。

当前状态：

- `AgentFlowConfig` 已加入 `app/config.py`。
- `config.yaml` 与 `k8s-configmap.yaml` 已加入 `agentflow` 配置段，默认 `enabled: true`。
- 已支持 `AGENTFLOW_RUNS_DIR`、`AGENTFLOW_MAX_CONCURRENT_RUNS` 环境变量覆盖。
- 服务启动日志已打印 `agentflow_enabled`。

### 阶段 3：AgentFlow 单入口 `[DONE]`

目标：让服务运行入口固定为 AgentFlow，移除运行时引擎切换。

改动文件：

- `app/unpacker_engine.py`

建议改动：

- `run_unpack()` 只调用 `run_unpack_agentflow()`：

```python
def run_unpack(firmware_path: str, output_path: str, cancel_check=None) -> dict:
    return run_unpack_agentflow(firmware_path, output_path, cancel_check=cancel_check)
```

验收：

- `run_unpack()` 只会进入 AgentFlow。
- AgentFlow 异常向外抛出，由任务管理器标记失败。
- `task_manager` 调用点无需改变。

当前状态：

- `run_unpack()` 已固定调用 `run_unpack_agentflow()`。
- 已移除运行时引擎模式配置。
- `task_manager` 已继续调用 `run_unpack()`，并传入 `task_id/project_id`。

### 阶段 4：新增 AgentFlow pipeline builder `[DONE]`

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

当前状态：

- `app/agentflow_pipeline.py` 已新增。
- 当前图已包含 `preprocess`、`feature_match`、`skill_executor`、`skill_reviewer`、`generic_executor`、`generic_reviewer`、`skill_author`、`cleanup`、`finalize`。
- reviewer success criteria 当前使用 `AGENTFLOW_REVIEW_(SUCCESS|SKIPPED)` marker。
- 单测已覆盖节点集合、关键依赖、reviewer success criteria。
- 与原 `app/agent/prompt/*.md` 的复用还不完全，当前更多依赖 marker 协议 prompt；后续可逐步收敛。

### 阶段 5：新增 AgentFlow runner `[PARTIAL]`

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

当前状态：

- `app/agentflow_runner.py` 已新增，负责构建 pipeline、创建 `RunStore`/`Orchestrator`、等待 run、处理取消、读取节点输出并转换 result dict。
- 已写入 `agentflow_run_id.txt`、`final_result.json`、stage 日志和 `tokens_summary.json`。
- 取消逻辑已在等待循环中调用 `orchestrator.cancel(run_id)`。
- 尚缺 runner 层 mock 单测，尤其是 success、failed、cancelled、preprocess success、skill success、generic success 的结果适配覆盖。
- `tokens_summary.json` 目前为占位结构，还没有聚合 AgentFlow/pi token。

### 阶段 6：迁移最小可用图 `[PARTIAL]`

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

- AgentFlow 单模式下任务可完成。
- 输出目录结构与现有任务目录约定基本一致。
- DB 中 `status/result_status/result_message/rounds` 正确。
- 失败任务能看到 AgentFlow run 目录和 node 输出。

当前状态：

- 最小链路已包含在当前完整图中。
- preprocess 成功、skill 成功等条件跳过通过节点 prompt 中的 `SKIPPED` marker 实现。
- 尚未记录真实 AgentFlow 服务级 smoke 结果；该项是下一轮最优先验收。

### 阶段 7：迁移 skill 匹配和 skill 执行 `[PARTIAL]`

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
- `matched_skill/matched_skill_version/matched_skill_score/fallback_to_llm` 字段与现有 DB/API 兼容。

当前状态：

- `feature_match` 节点已调用 `extract_firmware_features()`、`compute_family_id()`、`match_skill()`。
- runner 已在 skill review success 后调用 `register_skill_success()`。
- runner 已返回 `matched_skill`、`matched_skill_version`、`matched_skill_score`、`fallback_to_llm`。
- 尚缺命中 skill 成功、skill 失败 fallback generic 的集成或 mock 验证。

### 阶段 8：迁移 skill author `[PARTIAL]`

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

当前状态：

- `skill_author` 节点已加入图。
- runner 已在 generic success 且 author 输出非 `SKIPPED` 时调用 `save_candidate_skill()`。
- runner 已返回 `generated_skill_path`、`generated_skill_status`、`promotion_success_count`。
- 尚缺真实成功解包后候选 skill 生成验证；生成失败不影响主任务成功的异常路径也需要测试。

### 阶段 9：日志、可观测性和管理接口增强 `[DONE]`

目标：让 AgentFlow 运行结果能被 API 和运维定位。

建议增强：

- DB 增加字段：
  - `agentflow_run_id`
  - `engine_error`
- `TaskResponse` 增加：
  - `agentflow_run_id`
  - `run_path`
- 任务详情接口可返回 AgentFlow run id。
- 可选新增接口：
  - `GET /api/app/firmware-unpacker/tasks/{task_id}/agentflow`
  - 返回 run 状态、节点列表、失败节点、trace 路径。

验收：

- 线上可以通过 task id 定位 AgentFlow run。
- 失败节点的 output 和 error 可查。
- 旧客户端不受新增字段影响。

当前状态：

- `app/model.py` 已新增 `agentflow_run_id`、`engine_error`、`run_path` 字段，并有自动补列逻辑。
- `app/schemas.py` 已在 `TaskResponse` 暴露新增字段。
- `app/services/task_manager.py` 已将 AgentFlow result 字段写回 DB。
- `app/api/firmware.py` 已新增 project-scoped 和旧版任务路径的 AgentFlow 状态接口。
- 旧客户端兼容性通过 optional 字段保持。

### 阶段 10：生产灰度与切换 `[TODO]`

目标：安全切换到 AgentFlow 单入口镜像。

建议流程：

1. 部署包含 AgentFlow 单入口的镜像。
2. 在测试环境跑固定样本集：
   - 成功率。
   - 平均耗时。
   - token 消耗。
   - 输出目录完整性。
   - reviewer 通过率。
3. 在生产中按单 Pod 或单命名空间滚动。
4. 观察任务失败率和资源使用。
5. 完成生产切换。

验收：

- AgentFlow 单入口任务成功率达到上线要求。
- 平均耗时和资源占用在可接受范围内。
- 回滚只需要改配置，不需要重新构建镜像。

当前状态：

- 尚未执行测试环境固定样本集。
- 尚未进入生产单 Pod 或命名空间灰度。

## 6. 文件级改动清单

### 必改

- `Dockerfile`
  - 拷贝并安装 `agentflow/`。
  - 确认容器内 `agentflow` 和 `pi` 均可用。
  - 状态：`[DONE]`

- `requirements.txt`
  - 补充 AgentFlow 运行依赖，或依赖 `pip install -e /app/agentflow` 自动解析。
  - 状态：`[DONE]`，当前通过 Dockerfile editable install 本地 `agentflow/`。

- `app/config.py`
  - 增加 `AgentFlowConfig`。
  - 支持 env override。
  - 状态：`[DONE]`

- `config.yaml`
  - 增加 `agentflow` 配置段。
  - 状态：`[DONE]`

- `app/unpacker_engine.py`
  - `run_unpack()` 固定调用 AgentFlow runner。
  - 状态：`[DONE]`

- `app/agentflow_pipeline.py`
  - 新增 pipeline 构建逻辑。
  - 状态：`[DONE]`

- `app/agentflow_runner.py`
  - 新增运行、等待、取消、结果适配逻辑。
  - 状态：`[PARTIAL]`，代码已落地，缺少 runner mock 测试和真实 run smoke。

### 建议改

- `app/model.py`
  - 增加 `agentflow_run_id`、`engine_error`、`run_path` 等字段。
  - 状态：`[DONE]`

- `app/schemas.py`
  - 在任务响应中暴露 run 信息。
  - 状态：`[DONE]`

- `app/api/firmware.py`
  - 可选新增 AgentFlow run 状态接口。
  - 状态：`[DONE]`

- `app/services/task_manager.py`
  - 可选将 `task_id/project_id` 传入 `run_unpack()`，便于 runner 保存 run 映射。
  - 状态：`[DONE]`

- `README.md`
  - 补充 AgentFlow 配置和运行说明。
  - 状态：`[TODO]`

- `k8s-configmap.yaml`
  - 增加 agentflow 配置。
  - 状态：`[DONE]`

- `k8s-deployment.yaml`
  - 增加 AgentFlow runs 目录挂载或环境变量。
  - 状态：`[TODO]`，需确认当前 `/data/files` 挂载是否已覆盖 `run/agentflow` 和全局 `runs_dir` 需求。

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

AgentFlow 最终必须返回当前 `_update_task_result()` 可处理的字段：

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
- AgentFlow runner 取消当前 run。

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

- 固定样本集先在测试环境跑通。
- 分环境、分 Pod 滚动。
- 通过镜像回滚处理严重问题。

## 11. 测试计划

当前测试基线：

- 已执行 `pytest -q`，结果为 `12 passed in 0.21s`。
- 已覆盖配置默认值、环境变量覆盖、pipeline 节点和依赖、`run_unpack()` AgentFlow 分发。
- 尚未覆盖 AgentFlow runner 的真实状态适配，也未完成容器/服务级 AgentFlow smoke。

### 单元测试

- pipeline 构造测试：
  - 节点 ID 完整。
  - 依赖关系正确。
  - `PipelineSpec` 校验通过。
  - 状态：`[DONE]`
- result adapter 测试：
  - preprocess success。
  - skill success。
  - skill failed fallback generic success。
  - max retries reached。
  - cancelled。
  - 状态：`[TODO]`
- config 测试：
  - 默认 AgentFlow。
  - env override 生效。
  - 状态：`[DONE]`
- 入口分发测试：
  - `run_unpack()` 调用 AgentFlow。
  - AgentFlow 抛错时不 fallback。
  - 状态：`[DONE]`

### 集成测试

- 容器内 smoke：

```bash
python -c "import agentflow"
pi --version
```

状态：`[TODO]`，Dockerfile 已包含构建层校验，但还需要在目标构建环境记录一次实际结果。

- 服务级 smoke：

```bash
POST /api/app/firmware-unpacker/projects/{project_id}/tasks
GET  /api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}
```

状态：`[TODO]`

- AgentFlow run 检查：
  - run id 已写入 run 目录。
  - node outputs 可查。
  - final_result.json 存在。

状态：`[TODO]`

- AgentFlow 小样本 smoke：

```bash
pytest -q tests/test_agentflow_migration.py
```

状态：`[TODO]`，需要补测试或脚本，当前测试没有真实执行 AgentFlow/pi 节点。

### 回归测试

- agentflow mode 下核心任务测试通过。
  - 状态：`[TODO]`
- 模拟 AgentFlow 抛错后任务被标记失败。
  - 状态：`[DONE]`

## 12. 里程碑

### M1：运行时接入

交付物：

- Docker 镜像内 AgentFlow 可 import。
- 配置中存在 agentflow 段。
- 默认 AgentFlow。

状态：`[DONE]`

### M2：AgentFlow 单入口

交付物：

- `run_unpack()` 固定调用 AgentFlow runner。
- 不再暴露引擎模式配置。

状态：`[DONE]`

### M3：最小 AgentFlow 解包链路

交付物：

- `preprocess -> generic_executor -> reviewer -> cleanup -> finalize` 跑通。
- DB 状态正确。
- AgentFlow run 日志可查。

状态：`[PARTIAL]`，代码已落地，真实 AgentFlow/pi smoke 未完成。

### M4：完整 skill 链路

交付物：

- skill match、skill executor、skill reviewer、promotion count 迁移完成。
- skill fallback generic 正常。

状态：`[PARTIAL]`，代码已接入，缺少命中 skill 和 fallback 的集成验证。

### M5：skill author 与观测完善

交付物：

- candidate skill 生成迁移完成。
- run id 和节点状态可观测。

状态：`[PARTIAL]`，观测字段和接口已完成，candidate skill 生成仍缺真实验证。

### M6：灰度上线

交付物：

- 测试环境默认 agentflow。
- 生产灰度完成。
- 默认入口为 AgentFlow。

状态：`[TODO]`

## 13. 建议实施顺序

建议按以下顺序继续实施。前 1-3 项已完成，当前应从第 4 项继续：

1. `[DONE]` 新增配置和 Docker AgentFlow 安装。
2. `[DONE]` 固定 AgentFlow 单入口。
3. `[DONE]` 新增 AgentFlow runner 和 pipeline builder。
4. `[NEXT]` 补 AgentFlow runner mock 测试，覆盖 result adapter 和取消。
5. `[NEXT]` 跑通最小 AgentFlow pipeline 的真实 smoke。
6. `[NEXT]` 验证 AgentFlow 异常时任务失败状态和 run 日志。
7. `[NEXT]` 验证 skill match、skill executor、skill fallback。
8. `[NEXT]` 验证 skill author 候选 skill 生成。
9. `[NEXT]` 补 README 和 k8s deployment 挂载/环境变量说明。
10. `[TODO]` 测试环境启用 agentflow。
11. `[TODO]` 生产灰度。

## 14. 回滚方案

最快回滚：

- 回滚到上一版镜像。
- 或临时构建不包含当前 AgentFlow 单入口改动的镜像。

如果 AgentFlow 安装导致镜像启动失败：

- 回滚到上一版镜像。
- 或临时构建不包含 AgentFlow 安装层的镜像。

如果单个任务失败：

- DB 中保留失败前的 AgentFlow run id 供排查。
- 通过任务重试机制重新运行。

## 15. 后续增强方向

迁移稳定后可以继续利用 AgentFlow 能力：

- 多 reviewer fanout，降低误判。
- 多策略 candidate output，并行尝试不同解包路线。
- merge 节点选择最佳输出。
- 使用远程 EC2/ECS target 执行高资源消耗解包。
- 使用 scratchboard 保存跨节点分析结论。
- 为常见固件族构建 tuned agent。
- 将 AgentFlow web UI 暴露为内部调试页面。
