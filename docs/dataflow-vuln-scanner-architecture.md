# dataflow-vuln-scanner 架构设计

## 1. 定位

dataflow-vuln-scanner 是 SecFlow 平台中的 **JSON 配置驱动的可编排 AI 工作流引擎**。它接收上游 dataflow-analyse 产出的数据流污点分析结果和对应的 C/C++ 源码，通过 **Worker → 自我反思 → 全局评审 → 结果评审 → (循环)** 的多轮闭环，执行基于数据流证据的漏洞挖掘。

与后续演进的 `dataflow-vuln-scan`（新一代架构）不同，本系统是一个**通用 AI 工作流框架**，其漏洞挖掘能力是框架的一种具体应用配置。系统通过 JSON 配置文件定义智能体、工作流、角色和评审策略，通过 Python 插件实现业务逻辑扩展——这种"配置定义行为、插件扩展能力"的设计使其不仅可用于漏洞挖掘，也可适配其他多阶段 AI 分析任务。

> **说明**：本文档描述的是经典版 `dataflow-vuln-scanner`（代码位于 `secflow-app-dataflow-vuln-scanner/`）。新一代架构 `dataflow-vuln-scan` 的架构文档见 `dataflow-vuln-scan-architecture.md`。

## 2. 挑战

漏洞挖掘工作流引擎面临三个核心矛盾：

**分析深度与评审成本的矛盾。** 让 LLM Worker 深入分析污点传播路径中的每一个危险操作需要大量的 tool call（读源码、查交叉引用、验证条件分支），单次 Worker 分析可能需要 50-200 次 tool call。但 Worker 的输出质量波动大——可能遗漏关键 sink，也可能产生误报。需要一个高效的评审闭环来拦截低质量输出，同时避免评审本身消耗过多 LLM 算力。

**通用性与专用性的矛盾。** 框架需要支持多种 AI 分析场景（漏洞挖掘、系统分析、解包分析等），但每种场景的 Prompt、评审策略、插件链都完全不同。需要一种配置驱动的方式在"通用框架"和"专用行为"之间解耦。

**多智能体协同的上下文管理。** Worker、全局评审员、结果评审员各有不同的角色定位和工具权限。Worker 需要读写权限（分析源码 + 产出报告），评审员只需要只读权限（验证产物）。如何在同一个框架中管理这些角色，同时保证每次评审的独立性（不被此前分析上下文污染）？

dataflow-vuln-scanner 的解法是 **"JSON 配置定义 Pipeline + Python 插件链 + 三级评审闭环"** 三层架构。通过配置将智能体定义、工作流阶段、评审策略和插件链完全外置，框架本身只负责执行调度和状态管理。

## 3. 核心能力

系统回答三个问题：

| | 问题 | 方式 |
|:---|:---|:---|
| ① | 数据流污点传播路径中存在哪些潜在安全漏洞？ | Worker Agent（pi-worker）：以数据流标记（INPUT/DIRECT_SINK/USED/EXPORT/CLEANED/★）为主轴，回源码验证攻击者可控性和校验缺口 |
| ② | Worker 的分析覆盖度是否足够？是否遗漏了关键路径？ | 全局评审（Global Review）：两个并行 Advisor（全面性 + 深入性），评审覆盖度并输出 issues 清单驱动 rework |
| ③ | Worker 产出的漏洞报告是否是真实漏洞（非误报）？ | 结果评审（Result Review）：逐报告验证底层缺陷是否真实存在，标注 CONFIRMED / FALSE_POSITIVE |

## 4. 总体架构

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    SecFlow 平台 (前端 / API Gateway)                       │
│                    /api/dataflow-vuln-scanner                            │
└────────────────────────────┬─────────────────────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────────────────────┐
│           dataflow-vuln-scanner 服务 (FastAPI, Python)                    │
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────┐    │
│  │   API Layer      │  │  Manager Role    │  │   Worker Role      │    │
│  │                   │  │                   │  │                    │    │
│  │  • POST /tasks    │  │  • 任务调度       │  │  • 任务消费        │    │
│  │  • GET /tasks     │  │  • 状态流转       │  │  • 子进程执行      │    │
│  │  • Worker Jobs    │  │  • 配置下发       │  │  • Agent 调用      │    │
│  │  • Profiles       │  │  • LLM Provider   │  │  • 进度上报        │    │
│  │  • Vuln Reports   │  │  • Drain 优雅退出 │  │  • 卡死检测        │    │
│  │  • Health/Ready   │  │                   │  │                    │    │
│  └────────┬─────────┘  └────────┬─────────┘  └─────────┬──────────┘    │
│           │                     │                      │                │
│           └─────────────────────┴──────────────────────┘                │
│                                 │                                        │
│  ┌──────────────────────────────▼────────────────────────────────────┐  │
│  │                 pi_vuln_core 框架引擎                               │  │
│  │                                                                     │  │
│  │  ┌───────────────────────────────────────────────────────────────┐ │  │
│  │  │              CompositeWorkflowEngine (composite.py)            │ │  │
│  │  │                                                               │ │  │
│  │  │  按 stage.sequence 顺序执行各阶段                               │ │  │
│  │  │  支持嵌套组合工作流、阶段间不可回退                              │ │  │
│  │  │                                                               │ │  │
│  │  │  Stage 1: vuln_scan (Atomic)                                  │ │  │
│  │  │    │                                                          │ │  │
│  │  │    ▼                                                          │ │  │
│  │  │  ┌─────────────────────────────────────────────────────────┐ │ │  │
│  │  │  │           AtomicWorkflowEngine (atomic.py)               │ │ │  │
│  │  │  │                                                         │ │ │  │
│  │  │  │  完整生命周期 (每个 Review Cycle):                        │ │ │  │
│  │  │  │                                                         │ │ │  │
│  │  │  │  Start Plugins ──→ Worker ──→ Reflection ──→ Summary   │ │ │  │
│  │  │  │       │               │           │            │        │ │ │  │
│  │  │  │       └── 环境初始化  │           │            │        │ │ │  │
│  │  │  │                      │           │            │        │ │ │  │
│  │  │  │  ┌───────────────────┘           │            │        │ │ │  │
│  │  │  │  │  pi-worker Agent              │            │        │ │ │  │
│  │  │  │  │  (RPC mode, 跨轮复用 session)  │            │        │ │ │  │
│  │  │  │  │  产出: results/result_NNN.md  │            │        │ │ │  │
│  │  │  │  └───────────────────────────────┘            │        │ │ │  │
│  │  │  │                                               │        │ │ │  │
│  │  │  │  ┌── 自我反思 (reflect_completeness.md)       │        │ │ │  │
│  │  │  │  │   检查数据流覆盖度和分析深度                │        │ │ │  │
│  │  │  │  └───────────────────────────────────────────┘        │ │ │  │
│  │  │  │                                                       │ │ │  │
│  │  │  │  ┌── 总结 (summary.md)                                │ │ │  │
│  │  │  │  │   产出: summary.md + results/                      │ │ │  │
│  │  │  │  └───────────────────────────────────────────────────┘ │ │ │  │
│  │  │  │                                                       │ │ │  │
│  │  │  │  ┌── 全局评审 (Global Review) ─── 2 个 Advisor 并行   │ │ │  │
│  │  │  │  │   • global_completeness: 全面性审计 (覆盖度)        │ │ │  │
│  │  │  │  │   • global_depth: 深入性审计 (分析质量)             │ │ │  │
│  │  │  │  │   任一不通过 → 产出 issues → 回到 Worker (rework)  │ │ │  │
│  │  │  │  └───────────────────────────────────────────────────┘ │ │ │  │
│  │  │  │                                                       │ │ │  │
│  │  │  │  ┌── 结果评审 (Result Review) ── 逐报告并行验证       │ │ │  │
│  │  │  │  │   • result_fp_check: 误报检测                      │ │ │  │
│  │  │  │  │   每个 result_NNN.md → CONFIRMED / FALSE_POSITIVE  │ │ │  │
│  │  │  │  │   不通过项 → 标记 failed → 下轮 Worker 修复        │ │ │  │
│  │  │  │  └───────────────────────────────────────────────────┘ │ │ │  │
│  │  │  │                                                       │ │ │  │
│  │  │  │  循环直到: max_review_cycles 达到 或 全部通过          │ │ │  │
│  │  │  │                                                       │ │ │  │
│  │  │  │  End Plugins ──→ 归档 → 收集最终产出 → 生成下一阶段   │ │ │  │
│  │  │  └─────────────────────────────────────────────────────────┘ │ │  │
│  │  └───────────────────────────────────────────────────────────────┘ │  │
│  │                                                                     │  │
│  │  ┌───────────────────────────────────────────────────────────────┐ │  │
│  │  │                    横切关注点                                   │ │  │
│  │  │                                                               │ │  │
│  │  │  • agents/          — 4 种 Agent 运行时                       │ │  │
│  │  │    (pi_agent / claude_code / codex / opencode)               │ │  │
│  │  │  • plugins/         — 6 种内置插件 + 可扩展机制               │ │  │
│  │  │  • review/          — 三级评审系统                            │ │  │
│  │  │    (global_review / result_review / scheduler / state)        │ │  │
│  │  │  • engine/          — 工作流引擎                              │ │  │
│  │  │    (atomic / composite / worker / checkpoint)                 │ │  │
│  │  │  • recorder/        — 持久化记录与审计                        │ │  │
│  │  │  • resume.py        — 断点续跑 + 节点级恢复                  │ │  │
│  │  │  • observer.py      — 事件观察与 Dashboard 集成              │ │  │
│  │  └───────────────────────────────────────────────────────────────┘ │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

## 5. 核心引擎详解

### 5.1 组合工作流引擎 (CompositeWorkflowEngine)

组合工作流是多阶段流水线的顶层调度器，负责按 `stage.sequence` 顺序执行各阶段：

```
CompositeWorkflowEngine.run()
  │
  ├── Stage 1: vuln_scan (AtomicWorkflowEngine)
  │     └── 多轮 Review Cycle
  │
  ├── Stage 2: system_analysis (可选)
  │     └── ...
  │
  └── Stage N: ...
```

在当前漏洞挖掘场景中，组合工作流通常只包含一个 `vuln_scan` 阶段（`vuln_scan_pipeline`），但框架支持多阶段组合（如 `full_pipeline.json` 中包含 6 个阶段：解包分析 → 反编译优化 → 数据流分析 → 外部入口分析 → 系统分析 → 漏洞扫描）。

**关键设计**：
- 阶段间不可回退：一旦进入 Stage N，不会因为下游失败而回到 Stage N-1
- 支持嵌套组合工作流：一个 Stage 可以引用另一个 CompositeWorkflow
- 一对一任务传递（非扇出）：当前阶段输出 → 下一阶段输入

### 5.2 原子工作流引擎 (AtomicWorkflowEngine)

原子工作流是实际执行漏洞挖掘逻辑的核心引擎，实现完整的多轮 Review Cycle：

```
AtomicWorkflowEngine.run()
  │
  ├── Start Plugins (env_setup → workspace_init → task_validator)
  │
  └── FOR cycle IN 1..max_review_cycles:
        │
        ├── [Phase 1] Worker 分析
        │     • pi-worker Agent (RPC mode, 跨轮复用 session)
        │     • 输入: task.md + 数据流目录 + 源码目录
        │     • 产出: results/result_NNN.md + supporting_docs/
        │     • 必要时注入 rework 指令（来自上一轮 review issues）
        │
        ├── [Phase 2] 自我反思 (Reflection)
        │     • 读取 reflect_completeness.md prompt
        │     • Worker 检查自身覆盖度 (数据流标记覆盖、分析深度)
        │
        ├── [Phase 3] 总结 (Summary)
        │     • Worker 产出 summary.md + 更新 results/
        │
        ├── [Phase 4] 全局评审 (Global Review)
        │     • 2 个 Advisor 并行评审:
        │       - global_completeness: 全面性审计（覆盖度评分 + issues）
        │       - global_depth: 深入性审计（分析质量评分 + issues）
        │     • 任一不通过 (passed=false) → 整体不通过
        │     • 产出 issues 列表 → 注入 Worker 下一轮 rework
        │
        ├── [Phase 5] 结果评审 (Result Review)
        │     • 1 个 Advisor 逐报告评审:
        │       - result_fp_check: 误报检测
        │     • 每个 result_NNN.md → CONFIRMED / FALSE_POSITIVE
        │     • 支持并行评审 (parallel_result_review_limit=3)
        │     • 已通过项 (re_review_on_cycle=false) 不重审
        │
        └── 通过条件:
              • 全局评审全部通过 AND
              • 所有结果报告通过评审 AND
              • cycle >= min_discovery_cycles_before_pass
              → 循环结束
            否则 → cycle+1 → 回到 Phase 1 (带 rework 指令)

  └── End Plugins (result_archiver → final_output_collector → next_task_generator)
```

**关键设计决策**：

| 设计点 | Worker (pi-worker) | Advisor (pi-advisor) |
|:---|:---|:---|
| Session 策略 | `reset_worker_session_per_cycle=false` — 跨轮复用 RPC session | `reset_context=true` — 每轮全新上下文 |
| 工具权限 | 读写（read, bash, edit, write, grep, find） | 只读（read, bash, grep, find） |
| 思考级别 | 可配（low/medium/high/xhigh） | 跟随 worker 配置 |
| 重试策略 | RPC mode 内建 auto-retry | RPC mode 内建 auto-retry + 可选 advisor_runtime_retries |

### 5.3 Worker 执行器 (WorkerExecutor)

Worker 执行器管理 pi-worker Agent 的完整生命周期：

```
WorkerExecutor
  ├── _execute_worker_task()   — 首次分析（worker_system.md + worker_user.md）
  ├── _execute_rework()        — 带 rework 指令的分析（worker_rework_missed_hunt.md）
  ├── _execute_reflection()    — 自我反思（reflect_completeness.md）
  └── _execute_summary()       — 总结聚合（summary.md）

RPC mode 优势:
  • 跨轮复用同一 pi 进程和 session 文件
  • 上下文在内存中保持，不需要每轮重新加载
  • pi 内建 auto-retry 处理网络/限流错误
```

### 5.4 三级评审闭环

```
┌──────────────────────────────────────────────────────────────┐
│                    三级评审体系                                │
│                                                              │
│  Level 1: 自我反思 (Reflection)                              │
│    • 执行者: pi-worker (在同一个 session 中)                  │
│    • 时机: Worker 产出 results 之后，Summary 之前             │
│    • 目标: 检查数据流覆盖度和分析深度                         │
│    • Prompt: reflect_completeness.md                         │
│                                                              │
│  Level 2: 全局评审 (Global Review)                           │
│    • 执行者: 2 个 pi-advisor 并行                            │
│    • 时机: Summary 产出之后                                   │
│    • 目标: 审计分析覆盖度和深入性                             │
│    • 产物: passed/failed + scores + issues[]                 │
│    • 规则: 任一不通过 → 整体不通过 → 回到 Worker rework      │
│    • Prompt: global_review_completeness_user.md              │
│             global_review_depth_user.md                      │
│                                                              │
│  Level 3: 结果评审 (Result Review)                           │
│    • 执行者: 1 个 pi-advisor                                 │
│    • 时机: 全局评审通过之后                                   │
│    • 目标: 逐报告验证误报                                     │
│    • 产物: CONFIRMED / FALSE_POSITIVE                        │
│    • 并发: 默认 3 并行 (parallel_result_review_limit)        │
│    • Prompt: result_review_sys.md + result_review_user.md    │
└──────────────────────────────────────────────────────────────┘
```

**全局评审员的评分维度**（以 global_completeness 为例）：

| 维度 | 分值 | 说明 |
|:---|:---|:---|
| `coverage` | 0.0-1.0 | 关键入口函数、数据流标记（INPUT/DIRECT_SINK/USED/EXPORT/CLEANED/★）的覆盖度 |
| `input_coverage` | 0.0-1.0 | INPUT 标记是否被合理覆盖 |
| `export_followthrough` | 0.0-1.0 | EXPORT 是否至少跟到可判断边界 |
| `vuln_pattern_breadth` | 0.0-1.0 | 漏洞模式类型的广度 |
| `code_evidence_depth` | 0.0-1.0 | 源码证据的深度和质量 |
| `limitations_honesty` | 0.0-1.0 | 是否诚实记录了分析局限 |

**结果评审的验证逻辑**：

结果评审员的核心身份是"证伪者"（不是验证者）：它的目标不是"证明漏洞存在"而是"寻找漏洞不存在的证据"。检查顺序：
1. 代码点是否真实存在？
2. 底层缺陷是否真实（即使报告描述有偏差）？
3. 是否存在完整的拦截保护（被报告遗漏的校验）？
4. 是否只是表述偏差（问题本身真实但 exploitability 评估不准）？

## 6. 插件系统

### 6.1 6 种返回码

插件链的执行控制通过 6 种返回码实现：

| 返回码 | 语义 | 行为 |
|:---|:---|:---|
| `OK_NEXT` | 正常 | 执行下一个插件 |
| `OK_END_STAGE` | 正常，结束当前阶段 | 跳过后续插件 |
| `ERROR_CONTINUE` | 异常但可继续 | 执行下一个插件 |
| `ERROR_END_NEXT` | 异常，进入下一阶段 | 结束当前阶段并继续 |
| `ERROR_RESTART` | 历史兼容码 | 当前按失败退出处理 |
| `ERROR_EXIT` | 异常，立即退出 | 终止整个工作流 |

### 6.2 6 种内置插件

| 插件 ID | 类 | 阶段 | 职责 |
|:---|:---|:---|:---|
| `env_setup` | `EnvSetupPlugin` | Start | 环境变量注入、工作目录权限设置 |
| `workspace_init` | `WorkspaceInitPlugin` | Start | 创建 input/working/results/reviews/output 子目录 |
| `task_validator` | `TaskValidatorPlugin` | Start | 验证输入文件完整性（数据流文件 + 源码目录） |
| `result_archiver` | `ResultArchiverPlugin` | End | 将工作目录打包为 tar.gz 归档 |
| `final_output_collector` | `FinalOutputCollectorPlugin` | End | 收集最终产物到 output 目录（summary.md + results/ + index.json） |
| `next_task_generator` | `NextTaskGeneratorPlugin` | End | 为下一阶段生成任务定义（复合流水线场景） |

### 6.3 插件扩展机制

通过 `plugins/workflow_plugins.py` 可注册外部插件：

```python
# 插件注册示例
class CustomValidator(BasePlugin):
    def execute(self, ctx: PluginContext) -> PluginResult:
        # 自定义验证逻辑
        return PluginResult(code=PluginResultCode.OK_NEXT)
```

插件按配置中的 `start_plugins` 和 `end_plugins` 列表顺序串行执行，通过 `shared_state` 字典在插件间传递数据。

## 7. Agent 运行时

### 7.1 4 种 Agent 适配器

| 运行时 | 类 | 通信模式 | 适用场景 |
|:---|:---|:---|:---|
| `pi_agent` | `PiAgentRuntime` | RPC (stdin/stdout JSON-RPC) | **默认**，支持长连接 session 复用和内建 auto-retry |
| `claude_code` | `ClaudeCodeRuntime` | subprocess | Claude Code CLI 集成 |
| `codex` | `CodexRuntime` | subprocess | OpenAI Codex CLI 集成 |
| `opencode` | `OpenCodeRuntime` | subprocess | OpenCode CLI 集成 |

### 7.2 RPC Mode 详解

pi_agent 的 RPC mode 是默认且推荐的运行模式：

```
pi --mode rpc --session <session_file>
       ↑ stdin:  {"type":"prompt","message":"..."}
       ↓ stdout: JSONL events

特性:
  • 长连接复用: 同一 session 跨轮保持，Worker 上下文不丢失
  • 内建重试: pi 内部处理 API 限流/超时，框架无需额外重试逻辑
  • ARG_MAX 突破: prompt 通过 stdin 输入，无命令行长度限制
  • 超时处理: timeout_max_retries + timeout_retry_interval_seconds 控制超时后的自动重发

与旧版 JSON mode 的区别:
  JSON mode: 每次调用启动新 pi 进程 → 解析 JSON 输出 → 进程退出
  RPC mode:  一次启动 → 多轮对话 → 进程保持 → session 持久化
```

### 7.3 Review Profile 策略

系统通过 Review Profile 定义评审的激进程度：

| Profile | max_review_cycles | review_enabled | 说明 |
|:---|:---|:---|:---|
| `aggressive` | 10 | true | 最严格，多轮反复评审直到收敛 |
| `balanced` | 6 | true | **默认**，平衡评审深度与成本 |
| `conservative` | 3 | true | 快速评审，允许一定的覆盖度折衷 |
| `disabled` | 1 | false | 无评审，单次 Worker 产出即结束 |

Profile 同时控制：
- `min_discovery_cycles_before_pass` — 最少 discovery 轮数
- `progress_required_after_cycle` — 多少轮后必须有进展
- `progress_no_signal_closure_streak` — 连续无进展轮数后切换到 closure 模式
- `plateau_abort_streak` — 连续停滞轮数后中止

## 8. 数据模型

### 8.1 JSON 配置结构

```yaml
config.json
├── version: "1.0"
├── global:                           # 全局配置
│   ├── workspace_root               # 工作目录根路径
│   ├── max_review_cycles: 6         # 最大评审轮数
│   ├── parallel_result_review: true # 结果评审并行开关
│   └── parallel_result_review_limit: 3
│
├── agents: [AgentDef]               # 智能体定义
│   ├── id: "pi-worker"             # Worker 智能体
│   │   ├── type: "pi_agent"
│   │   ├── reset_context: false    # 跨轮复用 session
│   │   └── runtime_config:
│   │       ├── model: "icsl/zai-org/GLM-5"
│   │       ├── transport: "rpc"
│   │       └── sdk_specific: {thinking: "medium"}
│   │
│   └── id: "pi-advisor"            # Advisor 智能体
│       ├── type: "pi_agent"
│       ├── reset_context: true     # 每轮全新上下文
│       └── runtime_config: ...
│
├── plugins: [PluginDef]             # 插件定义链
│
├── workflows:                       # 工作流定义
│   ├── atomic: [AtomicWorkflowDef] # 原子工作流
│   │   └── vuln_scan:
│   │       ├── start_plugins / end_plugins
│   │       ├── engine: {max_review_cycles, review_profile, ...}
│   │       └── roles:
│   │           ├── worker: {agent_id, prompts: {work, reflection, summary}}
│   │           └── advisors: {global_review: [...], result_review: [...]}
│   │
│   └── composite: [CompositeWorkflowDef]  # 组合工作流
│       └── vuln_scan_pipeline:
│           └── stages: [{workflow_ref: "vuln_scan"}]
│
└── execution:                       # 执行入口
    ├── entry_workflow: "vuln_scan_pipeline"
    ├── input_task: {task_file, task_id}
    └── output_dir
```

### 8.2 任务状态流转

```
PENDING → QUEUED → RUNNING → COMPLETED / FAILED / CANCELLED
                  │
                  └── 子状态 (AtomicWorkflowState):
                        CREATED → PLUGINS_STARTED → WORKER_RUNNING
                        → REFLECTION_RUNNING → SUMMARY_RUNNING
                        → GLOBAL_REVIEW → RESULT_REVIEW
                        → (循环) → COMPLETED
```

### 8.3 漏洞输出结构

```
runs/{run_name}/workspace/vuln_scan_{task_id}/
├── input/task.md                      ← 自动生成的任务描述
├── working/                           ← Worker 工作目录
├── results/                           ← 漏洞报告
│   ├── result_001.md                  ← 单个漏洞详细报告
│   ├── result_002.md
│   └── ...
├── supporting_docs/                   ← 辅助分析文档
├── reviews/                           ← 评审记录
├── output/
│   └── final_output/                  ← 最终交付件
│       ├── summary.md                 ← 综合工作报告 + 漏洞汇总
│       ├── results/                   ← 最终确认的漏洞报告
│       └── index.json                 ← 产出索引
├── _meta/
│   ├── state.json                     ← 工作流状态
│   ├── vulnerability_list.json        ← 漏洞状态清单
│   │   └── counts: {confirmed, false_positive, pending_review}
│   ├── review_summaries/cycle_*.json  ← 每轮评审摘要
│   ├── cycle_metrics/cycle_*.json     ← 每轮指标
│   └── resume_preview.json            ← 续跑预览
└── sessions/                          ← Agent 对话历史
```

## 9. 服务架构与部署

### 9.1 三角色部署

| 角色 | Deployment | Replicas | 职责 |
|:---|:---|:---|:---|
| **api** | `secflow-app-dataflow-vuln-scanner-api` | 2 | REST API + 任务 CRUD + 服务注册 |
| **manager** | `secflow-app-dataflow-vuln-scanner-manager` | 2 | 任务调度 + 状态流转 + LLM Provider 同步 + 配置下发 |
| **worker** | `secflow-app-dataflow-vuln-scanner-worker` (StatefulSet) | 2 | 任务消费 + 子进程执行 + Agent 调用 + 进度上报。**单槽执行**（同时最多 1 个任务），每个任务启动前执行 Agent 进程清理 |

> **架构演进**：worker 角色已改为单槽模式——通过 `execution_service.py` 强制执行单任务约束，每个 worker Pod 同时只运行一个 `run_vuln_scan.py` 子进程。任务启动前自动清理残留的 pi Agent 进程，防止僵尸进程累积。多任务并发通过水平扩展 worker Pod 数量实现。

**三角色职责边界**：

```
api (接收请求) → manager (调度分配) → worker (执行分析)
                      │
                      ├── 扫描 pending 任务 → 按优先级排序
                      ├── 分配任务到空闲 worker (DB 租约)
                      └── 监控 worker 心跳 + 卡死回收
```

Worker 角色的优雅退出机制：`preStop` hook 发送 drain 请求，等待最多 45 秒让当前任务完成。

### 9.2 Agent 状态目录

系统支持两种任务用途，对应不同的 Agent 状态目录：

| 任务用途 | root_dir | 说明 |
|:---|:---|:---|
| `normal` | `/data/files/{project}/DATAFLOW_VULN_SCANNER/agent-state/shared/{agent_id}` | 共享目录，所有正常任务共用相同的 skills/memory |
| `evolution` | 创建时传入的自定义 `root_dir` | 独立目录，用于进化实验中的 A/B 测试 |

每个 agent 目录下包含：
- `skills/` — Agent 技能文档（Markdown）
- `memory/` — Agent 跨轮历史记忆

### 9.3 外部依赖

| 服务 | 用途 |
|:---|:---|
| MySQL | 任务状态、运行记录、事件持久化 |
| Nacos | 服务注册与发现 |
| LLM Provider API | AI 模型推理（通过 pi RPC 客户端） |
| NFS PVC (`/data`) | 共享文件系统（源码、输出、session 文件） |
| Harbor | Docker 镜像仓库 |

## 10. Prompt 体系

### 10.1 核心 Prompts

| Prompt 文件 | 使用者 | 用途 |
|:---|:---|:---|
| `worker_system.md` | pi-worker | 核心身份定义：data-flow driven vulnerability hunter |
| `worker_user.md` | pi-worker | 初始任务指令：读取数据流 + 源码 → 漏洞挖掘 |
| `worker_rework_missed_hunt.md` | pi-worker | 带 rework 指令的分析（注入上一轮 issues） |
| `worker_audit_appendix.md` | pi-worker | 审计附录生成指引 |
| `reflect_completeness.md` | pi-worker | 自我反思：检查数据流覆盖度和分析深度 |
| `summary.md` | pi-worker | 总结模板：汇总所有 findings + 生成结构化报告 |
| `global_review_completeness_user.md` | pi-advisor | 全面性审计：覆盖度评分 + issues + required_action |
| `global_review_depth_user.md` | pi-advisor | 深入性审计：分析质量评分 + issues |
| `result_review_sys.md` | pi-advisor | 误报检测系统提示词 |
| `result_review_user.md` | pi-advisor | 逐报告验证：核心检查顺序（代码真实性 → 底层缺陷 → 拦截保护 → 表述偏差） |

### 10.2 Pipeline Prompts（复合流水线场景）

```
prompts/pipeline/
├── data_flow_analysis/      ← 数据流分析阶段的 prompts
├── decompile_optimize/      ← 反编译优化阶段的 prompts
├── external_entry_analysis/ ← 外部入口分析阶段的 prompts
├── system_analysis/         ← 系统分析阶段的 prompts
├── unpack_analysis/         ← 解包分析阶段的 prompts
└── docker_system.md         ← Docker 执行环境系统提示
```

## 11. 一键启动器 (run_vuln_scan.py)

`run_vuln_scan.py` 是 CLI 便捷入口，自动完成以下步骤：

```
run_vuln_scan.py --data-flow /path/to/dataflow/ --source-dir /path/to/src/

  1. 扫描数据流目录
     • 发现 final_report.md 或 dataflow/*.md
     • 提取根函数名、跟踪函数数、数据流标记计数 (INPUT/DIRECT_SINK/USED/EXPORT/CLEANED)
     
  2. 扫描源码目录
     • 发现 files.list（模块文件清单）
     • 枚举 .c/.h/.cc/.cpp/.hpp/.asm/.s 文件
     
  3. 生成 task.md
     • 注入目标函数范围、数据流标记含义、源码文件清单
     • 指导 Worker 按数据流主轴 + 源码验证进行漏洞挖掘
     
  4. 生成 config.json
     • 合并默认配置 (config.vuln_scan_default.json) + CLI 参数
     • 解析相对 prompt 路径 → 绝对路径
     • 应用 Review Profile 策略
     
  5. 调用框架主程序
     • CompositeWorkflowEngine.run(entry_workflow="vuln_scan_pipeline")
     
  6. 监控进度 + 收集最终产物
```

## 12. 与新一代 dataflow-vuln-scan 的关系

| 维度 | dataflow-vuln-scanner (经典版) | dataflow-vuln-scan (新一代) |
|:---|:---|:---|
| **架构定位** | 通用 AI 工作流框架，漏洞挖掘是其中一种配置 | 专用数据流漏洞挖掘引擎 |
| **配置方式** | JSON 全量配置（agents + workflows + plugins + prompts） | 代码内建 Pipeline（固定三阶段） |
| **扩展性** | Python 插件链（6 种内置 + 可扩展） | 专用架构（通过 Prompt/Skill 定制行为） |
| **评审机制** | 三级评审闭环（自我反思 + 全局评审 + 结果评审） | 脚本校验图谱（vuln_graph_validator） |
| **图谱** | 无（纯文本报告） | SQLite 6 表持久化完整污点传播图 |
| **并发模型** | Worker + 2 个 Advisor 并行 | BFS Worker Pool + fork session |
| **漏洞发现** | Worker 自主发现 + Advisor 验证 | 图谱抽取 + 独立 fork session 判断 |
| **断点续跑** | 节点级 checkpoint + cycle 级恢复 | SQLite 持久化状态 |
| **Dashboard** | 内置 Streamlit Dashboard | 无独立 Dashboard |
| **适用场景** | 通用 AI 工作流（不仅限于漏洞扫描） | 专注数据流漏洞挖掘 |

> 经典版仍保留在代码库中以供参考和向后兼容。新任务统一使用 dataflow-vuln-scan，但经典版的框架能力（多阶段流水线、插件系统）在需要定制化工作流的场景中仍有价值。

## 13. 与 SecFlow 流水线的集成

dataflow-vuln-scanner 是 binary-security 端到端流水线的第五个阶段：

```
binary-security (总编排)
    │
    ▼
firmware-unpacker (固件解包)
    │
    ▼
system-analyse (模块分类 + 威胁分析)
    │
    ▼
binary-to-source (二进制逆向，可选)
    │
    ▼
entry-analyse (入口函数发现)
    │
    ▼
dataflow-analyse (污点传播追踪)
    │ 产物: dataflow/ + final_report.md
    ▼
dataflow-vuln-scanner (漏洞挖掘) ← 本节所述
    │ 输入: 数据流分析目录 + 源码目录
    │ 产物: final_output/summary.md + results/result_*.md
    │       + vulnerability_list.json
```

**上游输入契约**（来自 dataflow-analyse）：
```
- 数据流分析目录: 包含 final_report.md 和 dataflow/ 子目录
  • final_report.md: 根函数 + 调用链 + 数据流标记 (INPUT/DIRECT_SINK/USED/EXPORT/CLEANED/★)
  • dataflow/*.md: 每个被跟踪函数的详细污点分析
- 源码目录: 包含 .c/.h/.cc/.cpp/.hpp/.asm/.s 文件 或 files.list
```

## 14. 配置参考

| 参数 | 默认值 | 说明 |
|:---|:---|:---|
| `max_review_cycles` | 6 | 最大评审循环轮数 |
| `parallel_result_review` | true | 结果评审是否并行 |
| `parallel_result_review_limit` | 3 | 结果评审并发上限 |
| `review_profile` | balanced | 评审策略 (aggressive/balanced/conservative/disabled) |
| `min_discovery_cycles_before_pass` | 由 profile 控制 | 最少 discovery 轮次 |
| `reset_worker_session_per_cycle` | false | Worker 是否每轮重建 session |
| `transport` | rpc | pi 通信模式 (rpc/json) |
| `thinking` | medium | LLM 思考深度 (off/low/medium/high/xhigh) |
| `api_max_retries` | 0 (RPC mode 内建) | 框架侧 API 错误重试次数 |
| `pi_max_retries` | 0 (RPC mode 内建) | 框架侧 pi 进程崩溃重试次数 |
| `timeout_max_retries` | 3 | 超时后自动重发次数 |
| `timeout_retry_interval_seconds` | 30 | 超时重发间隔（秒） |
| `execution_timeout_seconds` | 0 (不限制) | `run_vuln_scan.py` 子进程最大执行时长 |
| `plateau_closure_streak` | 由 profile 控制 | 连续无进展轮数后切换到 closure 模式 |
| `plateau_abort_streak` | 由 profile 控制 | 连续停滞轮数后中止 |

## 15. 设计原则

| # | 原则 |
|:---|:---|
| 1 | **配置定义行为，框架只做调度** — 智能体、工作流、角色、评审策略、插件链全部通过 JSON 配置外置，框架代码零硬编码业务逻辑 |
| 2 | **JSON 配置即契约** — 配置文件完整定义了工作流的全部行为。修改配置（如替换 Prompt、调整评审策略）无需重新部署代码 |
| 3 | **三级评审闭环，独立验证** — 自我反思 → 全局评审 → 结果评审，每一级的评审者拥有独立上下文（reset_context=true），不做 Worker 的延伸 |
| 4 | **证伪优于证实** — 结果评审员的核心身份是"证伪者"而非"验证者"，目标不是证明漏洞存在而是寻找漏洞不存在的证据 |
| 5 | **Worker 有状态，Advisor 无状态** — Worker 跨轮复用 RPC session（`reset_context=false`），保留分析记忆；Advisor 每轮全新上下文（`reset_context=true`），保证评审独立性 |
| 6 | **插件链编排，6 种返回码控制流** — Start Plugins（初始化）→ Engine（核心循环）→ End Plugins（归档收集），插件通过返回码控制阶段流转 |
| 7 | **Plateau 检测，自动止损** — 连续多轮无进展时自动切换到 closure 模式或中止，避免无限消耗 LLM 算力 |
| 8 | **多 Agent 运行时适配** — 支持 pi_agent / claude_code / codex / opencode 四种运行时，通过统一的 AgentRuntime 接口切换 |
| 9 | **断点续跑，节点级恢复** — Checkpoint 机制支持 cycle 级和 step 级恢复，失败任务可从断点继续 |
| 10 | **数据流主轴优先** — Worker 的分析必须以数据流标记（INPUT/DIRECT_SINK/USED/EXPORT/CLEANED/★）为主轴，不做脱离数据流的无边界全项目重扫 |

## 16. 性能参考

| 场景 | 数据流文件数 | Review Cycles | 耗时 |
|:---|:---|:---|:---|
| 简单单函数（1-3 个漏洞候选） | 1-3 | 2-3 | 10-30 min |
| 中等模块（5-10 个被跟踪函数） | 5-10 | 3-5 | 30-90 min |
| 复杂模块（10-30 个被跟踪函数） | 10-30 | 4-6 | 1-4 h |

> 每轮 Review Cycle 包含：Worker 分析（5-15 min）+ 自我反思（1-3 min）+ 全局评审 × 2 并行（2-5 min）+ 结果评审 × N 并行（1-3 min/报告 × N）。实际耗时取决于 LLM Provider 的并发能力和数据流分析的复杂度。

---
> 文档版本：`v2.1` @ `5e4b6467` · 代码 `979076c1`（2026-06-05）
