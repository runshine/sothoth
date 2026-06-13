# dataflow-vuln-scanner 架构设计

## 1. 定位

dataflow-vuln-scanner 是 SecFlow 平台中的 **数据流驱动的 AI 漏洞挖掘引擎**。它接收上游 dataflow-analyse 产出的数据流污点分析结果和对应的 C/C++ 源码，通过 **Worker → 自我反思 → 总结 → 全局评审 → 结果评审 → (循环)** 的多轮闭环，执行基于数据流证据的深度漏洞挖掘。

系统采用 **"JSON 配置定义 Pipeline + Python 插件链 + 三级评审闭环"** 三层架构。智能体定义、工作流阶段、角色权限、评审策略和插件链全部通过 JSON 配置外置，框架本身只负责执行调度与状态管理。

## 2. 挑战

数据流驱动的漏洞挖掘面临三个核心挑战：

**覆盖度 vs 遗漏风险。** 一个中大型模块的数据流分析可能涉及数十个函数、数百个数据流标记（INPUT/DIRECT_SINK/USED/EXPORT/CLEANED/★），分布在多个调用链上。LLM Worker 在一次分析中容易聚焦显性危险点（如明显的 memcpy 无长度检查），但可能遗漏隐蔽的漏洞模式——整数溢出导致校验绕过、USE 点的间接消费、跨函数的类型混淆等。Worker 自己难以判断"是否覆盖够了"——它看到的漏洞就是它认为的全部漏洞。

**误报 vs 漏报的权衡。** 数据流标记提供了污点传播的骨架，但标记本身不包含校验的充分性判断。一个被标记为 DIRECT_SINK 的函数调用可能在更上层已有完整的输入校验，Worker 若只追踪数据流标记而不深入验证源码上下文，会产出大量误报。反之，过度保守则会漏掉真实漏洞。

**多轮分析的收敛控制。** 单轮分析不足以覆盖所有漏洞模式，但无限制的多轮迭代会导致 LLM 算力消耗失控。系统需要在"继续深挖的收益"和"算力成本"之间找到平衡点——既要给 Worker 足够的轮次去覆盖复杂路径，又要在覆盖度趋于饱和时及时收敛。

dataflow-vuln-scanner 的解法：

| 挑战 | 解法 |
|:---|:---|
| 覆盖度 vs 遗漏 | 三级评审闭环：自我反思（Worker 自查覆盖度）→ 全局评审（独立 Advisor 审计覆盖面和深度）→ 结果评审（逐报告验证真伪）。任一环节不通过则产出结构化 issues 驱动 Worker rework |
| 误报 vs 漏报 | 独立 Advisor 以"证伪者"身份验证每个漏洞报告——不证明漏洞存在，而是寻找漏洞不存在的证据（校验保护、边界条件、数据流截断） |
| 收敛控制 | Plateau 检测机制：多维指标（scores 趋势、产物指纹变化、新增结果数）判定是否停滞，自动从 discovery 切换到 closure 模式或提前中止，避免无效消耗 |

## 3. 核心能力

系统回答三个问题：

| | 问题 | 方式 |
|:---|:---|:---|
| ① | 数据流污点传播路径中存在哪些潜在安全漏洞？ | Worker Agent：以数据流标记（INPUT/DIRECT_SINK/USED/EXPORT/CLEANED/★）为主轴，回源码验证攻击者可控性和校验缺口 |
| ② | Worker 的分析覆盖度是否足够？是否遗漏了关键路径？ | 全局评审：两个并行 Advisor（全面性 + 深入性），审计覆盖度并输出 issues 驱动 rework |
| ③ | Worker 产出的漏洞报告是否是真实漏洞（非误报）？ | 结果评审：逐报告验证底层缺陷是否真实存在，标注 CONFIRMED / FALSE_POSITIVE |

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
│  │  • Vuln Reports   │  │  • Drain 优雅退出 │  │  • Agent 进程清理  │    │
│  │  • Admin Proxy    │  │  • 心跳监控       │  │  • 单槽执行        │    │
│  │  • Health/Ready   │  │  • 卡死回收       │  │                    │    │
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
│  │  │  on_error: abort / skip_task / skip_stage                      │ │  │
│  │  │                                                               │ │  │
│  │  │  vuln_scan_pipeline (单阶段):                                   │ │  │
│  │  │    Stage 1: vuln_scan (Atomic)                                 │ │  │
│  │  │                                                               │ │  │
│  │  │  full_vuln_pipeline (可选, 6 阶段全流水线):                      │ │  │
│  │  │    Stage 1-6: unpack → system_analysis → decompile →           │ │  │
│  │  │                entry_analysis → data_flow → vuln_scan          │ │  │
│  │  │                                                               │ │  │
│  │  │    ▼                                                          │ │  │
│  │  │  ┌─────────────────────────────────────────────────────────┐ │ │  │
│  │  │  │           AtomicWorkflowEngine (atomic.py)               │ │ │  │
│  │  │  │                                                         │ │ │  │
│  │  │  │  Start Plugins ──→ [Review Cycle Loop] ──→ End Plugins  │ │ │  │
│  │  │  │                                                         │ │ │  │
│  │  │  │  discovery 模式 (首轮或无需 rework):                      │ │ │  │
│  │  │  │    Worker → Reflection → Summary →                       │ │ │  │
│  │  │  │    Global Review → Result Review                         │ │ │  │
│  │  │  │                                                         │ │ │  │
│  │  │  │  rework 模式 (有评审 issues 反馈):                        │ │ │  │
│  │  │  │    Worker (双阶段 rework, 跳过 Reflection) →              │ │ │  │
│  │  │  │    Summary → Global Review → Result Review               │ │ │  │
│  │  │  │                                                         │ │ │  │
│  │  │  │  summary repair 模式 (summary 文档有问题时):              │ │ │  │
│  │  │  │    Summary (repair, 跳过 Worker 和 Reflection) →         │ │ │  │
│  │  │  │    Global Review → Result Review                         │ │ │  │
│  │  │  │                                                         │ │ │  │
│  │  │  │  循环直到: 评审全部通过 或 达到 max_review_cycles         │ │ │  │
│  │  │  │          或 Plateau 检测触发 abort                       │ │ │  │
│  │  │  └─────────────────────────────────────────────────────────┘ │ │  │
│  │  └───────────────────────────────────────────────────────────────┘ │  │
│  │                                                                     │  │
│  │  ┌───────────────────────────────────────────────────────────────┐ │  │
│  │  │                    横切关注点                                   │ │  │
│  │  │                                                               │ │  │
│  │  │  • agents/          — 4 种 Agent 运行时                       │ │  │
│  │  │    (pi_agent / claude_code / codex / opencode)               │ │  │
│  │  │  • plugins/         — 6 种内置插件 + 可扩展机制               │ │  │
│  │  │  • review/          — 三级评审 + 状态追踪 + 趋同控制          │ │  │
│  │  │    (global_review / result_review / scheduler / state /       │ │  │
│  │  │     profile / previous_limitations / read_only_guard)         │ │  │
│  │  │  • engine/          — 工作流引擎 + checkpoint                 │ │  │
│  │  │    (atomic / composite / worker / checkpoint)                 │ │  │
│  │  │  • recorder/        — 持久化记录与审计                        │ │  │
│  │  │  • resume.py        — 断点续跑 + 节点级恢复                  │ │  │
│  │  │  • observer.py      — 事件观察与 DB 集成                     │ │  │
│  │  │  • utils/           — 漏洞清单 / 结果文档 / 模板 / 日志      │ │  │
│  │  └───────────────────────────────────────────────────────────────┘ │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

## 5. 核心引擎详解

### 5.1 组合工作流引擎 (CompositeWorkflowEngine)

组合工作流是多阶段流水线的顶层调度器，按 `stage.sequence` 顺序执行各阶段。当前漏洞挖掘场景默认使用 `vuln_scan_pipeline`（仅含 1 个 `vuln_scan` 阶段）。框架同时提供 `full_vuln_pipeline`（6 阶段：解包分析 → 系统分析 → 反编译优化 → 外部入口分析 → 数据流分析 → 漏洞扫描），其中前 5 个阶段由 `docker-runner` agent 执行，最后 1 个阶段由 `pi-worker` + `pi-advisor` 执行。

**关键设计**：
- 阶段间不可回退：一旦进入 Stage N，不会因下游失败回到 Stage N-1
- 支持嵌套组合工作流：一个 Stage 可引用另一个 CompositeWorkflow
- 一对一任务传递：当前阶段所有 task 的输出汇总为下一阶段输入
- 错误处理：`on_error` 支持 `abort` / `skip_task` / `skip_stage`

### 5.2 原子工作流引擎 (AtomicWorkflowEngine)

原子工作流是执行漏洞挖掘的核心引擎。根据当前 cycle 上下文，有三种执行路径：

**路径 A — discovery 模式（首轮或无需 rework）**：
```
Start Plugins → Worker → Reflection → Summary → Global Review → Result Review
```

**路径 B — rework 模式（有评审 issues 反馈）**：
```
Worker (rework, 跳过 Reflection) → Summary → Global Review → Result Review
```
Rework 时 Worker 内部串行执行最多两个阶段：
1. `profile_driven_exploration` — 按审计档位深度预算继续探索
2. `missed_vuln_hunting` — 针对评审 issues 的遗漏漏洞定向追猎

两个阶段是否执行由 `_select_rework_stages()` 根据当前 route state 动态决定。

**路径 C — summary repair 模式（summary 文档有问题时）**：
```
Summary (repair, 跳过 Worker 和 Reflection) → Global Review → Result Review
```

**通过条件**：全局评审全部通过 AND 所有 active 结果报告通过结果评审 AND cycle >= `min_discovery_cycles_before_pass`。

**关键设计决策**：

| 设计点 | Worker (pi-worker) | Advisor (pi-advisor) |
|:---|:---|:---|
| Session 策略 | `reset_worker_session_per_cycle=false` — 跨轮复用 RPC session | `reset_context=true` — 每轮全新上下文 |
| 工具权限 | 读写（默认 pi agent 全工具集） | 只读（sdk_specific.tools="read,bash"，bash 仅用于 grep/find 等只读操作） |
| 思考级别 | 由 Profile 和模型能力自动决定 | 跟随 Profile 决定 |
| 重试策略 | RPC mode 内建 auto-retry | RPC mode 内建 auto-retry + JSON schema 修复重试 |
| 只读守卫 | 无 | read_only_guard 检测并报告越权写入 |

### 5.3 Worker 执行器 (WorkerExecutor)

```
WorkerExecutor
  ├── execute_worker()             — Worker 分析阶段
  │     • 首轮 (cycle=1): 使用 worker_user.md prompt
  │     • 后续轮次: 判定是否进入 rework
  │       - 有评审失败反馈/issues → _execute_rework_sequence()
  │       - 无反馈 → 继续 worker_user.md (discovery 续挖)
  │
  ├── _execute_rework_sequence()   — Rework 序列 (两个可选阶段)
  │     • Stage 1: profile_driven_exploration
  │         (prompt: worker_profile_driven_exploration.md)
  │         触发条件: profile 深度预算未耗尽
  │     • Stage 2: missed_vuln_hunting
  │         (prompt: worker_rework_missed_hunt.md)
  │         触发条件: 有 security worker issue entries
  │     • 两阶段串行执行，各自有独立 checkpoint
  │     • 完成后设置 skip_reflection_after_worker=True
  │
  ├── execute_reflection()         — 自我反思 (仅 discovery 模式)
  │     • rework 和 summary_repair 模式跳过
  │     • 默认 1 pass: reflect_completeness.md
  │     • 辅助: reflect_checklist_*.md
  │
  └── execute_summary()            — 总结聚合
        • prompt: summary.md
        • 支持 summary repair (不经 Worker/Reflection 直接修 summary)
```

### 5.4 三级评审闭环

```
┌──────────────────────────────────────────────────────────────┐
│                    三级评审体系                                │
│                                                              │
│  Level 1: 自我反思 (Reflection)                              │
│    • 执行者: pi-worker                                       │
│    • 时机: Worker 产出 results 之后，Summary 之前             │
│    • 仅 discovery 模式执行，rework/summary_repair 模式跳过    │
│    • 主 prompt: reflect_completeness.md                      │
│    • 辅助: reflect_checklist_initial.md / rework.md /        │
│           result_repair.md                                   │
│                                                              │
│  Level 2: 全局评审 (Global Review)                           │
│    • 执行者: 2 个 pi-advisor 并行                            │
│    • 时机: Summary 产出之后                                   │
│    • 评分维度:                                                │
│      - global_completeness → coverage (0.0-1.0)              │
│      - global_depth → vuln_pattern_breadth (0.0-1.0)         │
│    • 任一不通过 → 整体不通过 → 产出 issues → 回到 Worker     │
│    • 只读守卫 + JSON schema 修复重试 (默认 2 次)              │
│                                                              │
│  Level 3: 结果评审 (Result Review)                           │
│    • 执行者: 1 个 pi-advisor                                 │
│    • 时机: 全局评审通过之后                                   │
│    • 逐报告验证: CONFIRMED / FALSE_POSITIVE                  │
│    • 并发: 默认 3 并行 (parallel_result_review_limit)        │
│    • 指纹机制: 已通过且文件 SHA256 未变 → 跳过重审            │
│    • re_review_on_cycle=false: cycle>1 后不重审已通过项      │
└──────────────────────────────────────────────────────────────┘
```

**全局评审的两个实际评分维度**（来自配置中的 `score_fields`）：

| Advisor | 评分字段 | 说明 |
|:---|:---|:---|
| `global_completeness` | `coverage` | 关键入口函数、数据流标记（INPUT/DIRECT_SINK/USED/EXPORT/CLEANED/★）的覆盖完备度 |
| `global_depth` | `vuln_pattern_breadth` | 漏洞模式类型的覆盖广度 |

> 解析器 (`global_review_parser.py`) 定义了 8 个已知 score key（`coverage`, `input_coverage`, `export_followthrough`, `used_coverage`, `vuln_pattern_breadth`, `code_evidence_depth`, `limitations_honesty`, `report_completeness`），这些仅在 Advisor 输出的 JSON 解析和 schema 修复时作为模板参考。实际评分仅使用上述 2 个维度。

**结果评审的"证伪者"逻辑**：

结果评审员的目标不是"证明漏洞存在"而是"寻找漏洞不存在的证据"。检查顺序：
1. 代码点是否真实存在？
2. 底层缺陷是否真实（即使报告描述有偏差）？
3. 是否存在完整的拦截保护（被报告遗漏的校验）？
4. 是否只是表述偏差（问题本身真实但 exploitability 评估不准）？

### 5.5 评审状态追踪 (ReviewState)

`ReviewState` 是跨 cycle 的状态追踪器：

- **全局评审历史**：append-only 记录每轮每个 Advisor 的 passed/scores/issues/feedback
- **结果项状态**：每个 `result_NNN.md` 的通过/失败/生命周期（active/inactive）
- **文件指纹追踪**：SHA256 判断结果文件是否被修改（已通过但文件变化 → 必须重审）
- **反馈窗口**：Worker 收到最近 2 轮轻量反馈（`FEEDBACK_WINDOW=2`）
- **工作模式**：`discovery`（发现模式）→ `closure`（收敛模式），由 Plateau 检测触发

### 5.6 Plateau 检测与收敛控制

引擎通过 `_update_plateau_state()` 方法实现多维停滞检测，是控制评审循环收敛的核心机制。当一轮全局评审全部通过时，plateau streak 清零；当评审未通过时，系统综合以下信号判断是否停滞：

- **评分趋势**：最近 N 轮 scores 变化是否低于 `score_min_delta`（默认 0.03）
- **产物变化**：result 文件指纹是否保持稳定
- **新增结果**：是否有新的 unreviewed 结果产生
- **summary 更新**：summary 是否在本轮有实质性更新

一旦判定停滞（stagnant），系统累加 `plateau_streak`：
- 连续 `plateau_closure_streak` 轮（默认 2）→ 切换到 **closure 模式**，Worker 只验证 active backlog 和高风险源码缺口，不再发散探索
- 连续 `plateau_abort_streak` 轮（默认 3）→ **提前中止**，避免无限消耗 LLM 算力

在进入 abort 前，系统还会尝试 `summary_repair`（默认预算 2 次）作为最后的挽救手段。

关键参数：

| 参数 | 默认值 | 说明 |
|:---|:---|:---|
| `progress_no_signal_closure_streak` | 2 | 连续 N 轮无进展 → closure |
| `progress_no_signal_abort_streak` | 3 | 连续 N 轮停滞 → abort |
| `progress_required_after_cycle` | 0 | 从第 N 轮要求可量化进展（0=不要求） |
| `plateau_closure_streak` | 2 | Plateau closure 阈值 |
| `plateau_abort_streak` | 3 | Plateau abort 阈值 |
| `score_min_delta` | 0.03 | 评分变化低于此值视为停滞 |

### 5.7 漏洞状态清单 (Vulnerability List)

系统在 `_meta/vulnerability_list.json` 中维护结构化漏洞清单，三种状态：`pending_review`（待评审）、`confirmed`（确认）、`false_positive`（误报）。Worker 每轮产出后通过 `sync_vulnerability_list_from_results()` 自动同步，结果评审后通过 `apply_result_review_verdict()` 更新状态和指纹。

## 6. Review Profile 策略

### 6.1 三种评审策略

| Profile | max_review_cycles | review_enabled | 说明 |
|:---|:---|:---|:---|
| `fast` | 1 | false | 单轮扫描，不做多轮评审。聚焦显性数据流漏洞 |
| `balanced` | 6 | true | **默认**，标准深度：面向中高危与关键路径 |
| `audit` | 10 | true | 深度审计：追求最多、最深的可复核漏洞证据 |

> `EngineConfig` 的 `review_profile` 接受 `Literal["fast", "balanced", "strict", "audit"]`，`strict` 由 `normalize_review_profile()` 自动映射为 `audit`。

### 6.2 各 Profile 详细策略

| 维度 | fast | balanced | audit |
|:---|:---|:---|:---|
| 默认最大轮数 | 1 | 6 | 10 |
| 评审开关 | 关闭 | 开启 | 开启 |
| Worker 最大 turns/轮 | 80 | 140 | 260 |
| 最少 discovery 轮 | 1 | 1 | 3 |
| 要求进展起始轮 | 0 | 0 | 3 |
| 无信号 closure 连续轮 | 1 | 2 | 1 |
| 无信号 abort 连续轮 | 1 | 3 | 2 |
| 最少证据产物数 | 0 | 1 | 5 |
| 要求的漏洞模式族 | (无) | memory_safety, integer_safety, input_validation | 上述 + logic_state, resource_lifetime, concurrency_timing |
| 数据流抽取比例 | 0% | ≥50% | 100% |
| Worker stdout trace | 2 MB | 4 MB | 8 MB |
| Advisor stdout trace | 1 MB | 4 MB | 8 MB |

### 6.3 思考级别自动解析

`resolve_profile_thinking()` 根据模型能力（从 `~/.pi/agent/models.json` 读取）和 Review Profile 自动选择 LLM 思考深度：fast → 最低可用档，balanced → 中档，audit → 最高可用档。结果自动注入 `runtime_config.sdk_specific.thinking`。

## 7. 插件系统

### 7.1 6 种返回码

| 返回码 | 语义 | 行为 |
|:---|:---|:---|
| `OK_NEXT` | 正常 | 执行下一个插件 |
| `OK_END_STAGE` | 正常，结束当前阶段 | 跳过后续插件 |
| `ERROR_CONTINUE` | 异常但可继续 | 执行下一个插件 |
| `ERROR_END_NEXT` | 异常，进入下一阶段 | 结束当前阶段并继续 |
| `ERROR_RESTART` | 历史兼容码 | 按失败退出处理 |
| `ERROR_EXIT` | 异常，立即退出 | 终止整个工作流 |

### 7.2 6 种内置插件

| 插件 ID | 阶段 | 职责 |
|:---|:---|:---|
| `env_setup` | Start | 环境变量注入、工作目录权限设置 |
| `workspace_init` | Start | 创建 input/working/results/reviews/output 子目录 |
| `task_validator` | Start | 验证输入文件完整性（数据流文件 + 源码目录） |
| `result_archiver` | End | 工作目录打包为 tar.gz |
| `final_output_collector` | End | 收集最终产物到 output 目录，按 confirmed/false_positive/pending 分类 |
| `next_task_generator` | End | 为下一阶段生成任务定义 |

### 7.3 插件扩展

通过 `plugins/workflow_plugins.py` 注册外部插件，继承 `BasePlugin` 实现 `execute()` 方法。插件按 `start_plugins` / `end_plugins` 列表顺序串行执行，通过 `shared_state` 字典传递数据。

## 8. Agent 运行时

### 8.1 4 种 Agent 适配器

| 运行时 | 通信模式 | 适用场景 |
|:---|:---|:---|
| `pi_agent` | RPC (stdin/stdout JSON-RPC) | **默认**，长连接 session 复用 + 内建 auto-retry |
| `claude_code` | subprocess | Claude Code CLI 集成 |
| `codex` | subprocess | OpenAI Codex CLI 集成 |
| `opencode` | subprocess | OpenCode CLI 集成 |

### 8.2 RPC Mode

```
pi --mode rpc --session <session_file>
       ↑ stdin:  {"type":"prompt","message":"..."}
       ↓ stdout: JSONL events

特性:
  • 长连接复用: 同一 session 跨轮保持，Worker 上下文不丢失
  • 内建重试: pi 内部处理 API 限流/超时
  • ARG_MAX 突破: prompt 通过 stdin 输入
  • 超时处理: timeout_max_retries + timeout_retry_interval_seconds
  • stdout 限制: rpc_stdout_trace_bytes / rpc_stdout_abort_bytes
```

## 9. 数据模型

### 9.1 JSON 配置顶层结构

```yaml
config.json
├── version: "1.0"
├── global:                     # 全局配置
│   ├── workspace_root
│   ├── max_review_cycles: 6
│   ├── parallel_result_review: true
│   └── parallel_result_review_limit: 3
│
├── agents: [AgentDef]         # 智能体定义
│   └── id, name, type         # pi_agent / claude_code / codex / opencode
│       reset_context: bool
│       runtime_config: {...}  # model, transport, sdk_specific 等
│
├── plugins: [PluginDef]       # 插件定义
│   └── id, module_path, class_name, config
│
├── workflows:
│   ├── atomic: [AtomicWorkflowDef]
│   │   └── vuln_scan:
│   │       ├── start_plugins / end_plugins
│   │       ├── engine: {EngineConfig}  # 见 9.2 节
│   │       └── roles:
│   │           ├── worker: {agent_id, new_session, prompts: {work, reflection, summary}}
│   │           └── advisors:
│   │               ├── global_review: [{instance_id, agent_id, role_name,
│   │               │     re_review_on_cycle, user_prompt_template, score_fields}]
│   │               └── result_review: [{instance_id, agent_id, role_name,
│   │                     re_review_on_cycle, system_prompt_file, user_prompt_template}]
│   │
│   └── composite: [CompositeWorkflowDef]
│       ├── vuln_scan_pipeline   # 单阶段
│       └── full_vuln_pipeline   # 6 阶段全流水线
│
└── execution:                  # 执行入口
    ├── entry_workflow
    ├── input_task: {task_file, task_id}
    └── output_dir
```

### 9.2 EngineConfig 参数全集

| 参数 | 类型 | 默认值 | 说明 |
|:---|:---|:---|:---|
| `max_review_cycles` | int\|None | None | 最大评审轮数（None=使用 global） |
| `review_profile` | Literal | "balanced" | fast / balanced / strict / audit |
| `review_enabled` | bool | true | 是否启用评审 |
| `max_worker_turns_per_cycle` | int\|None | None | Worker 每轮最大 tool call 数 |
| `reflection_passes_per_cycle` | int\|None | None | 每轮反射 pass 数 |
| `reflection_max_internal_turns` | int\|None | None | 反射内部最大 turns |
| `reflection_rpc_stdout_trace_bytes` | int\|None | None | 反射 RPC stdout trace 限制 |
| `reflection_rpc_stdout_abort_bytes` | int\|None | None | 反射 RPC stdout abort 限制 |
| `min_discovery_cycles_before_pass` | int\|None | None | 最少 discovery 轮数才能通过 |
| `progress_required_after_cycle` | int | 0 | 从第 N 轮要求可量化进展 |
| `progress_no_signal_closure_streak` | int | 2 | 无进展 → closure 轮数 |
| `progress_no_signal_abort_streak` | int | 3 | 停滞 → abort 轮数 |
| `min_evidence_artifacts` | int\|None | None | 最少证据产物数 |
| `required_pattern_families` | list[str] | [] | 必须覆盖的漏洞模式族 |
| `reset_worker_session_per_cycle` | bool | false | Worker 每轮重建 session |
| `plateau_closure_streak` | int | 2 | Plateau closure 阈值 |
| `plateau_abort_streak` | int | 3 | Plateau abort 阈值 |
| `summary_repair_attempt_budget` | int | 2 | Summary 修复重试预算 |
| `global_review_schema_repair_limit` | int | 2 | 全局评审 JSON schema 修复次数 |
| `result_review_schema_repair_limit` | int | 2 | 结果评审 JSON schema 修复次数 |
| `global_review_fresh_session_schema_repair_limit` | int | 1 | 全局评审 fresh session 重试 |
| `result_review_fresh_session_schema_repair_limit` | int | 1 | 结果评审 fresh session 重试 |
| `score_min_delta` | float | 0.03 | 评分变化低于此值视为停滞 |

### 9.3 任务状态流转

```
PENDING → QUEUED → RUNNING → COMPLETED / FAILED / CANCELLED
                  │
                  ├── 调度子状态:
                  │     pending → queued → dispatching → starting → running
                  │
                  └── 原子工作流子状态:
                        CREATED → START_PLUGINS → WORKER → REFLECT
                        → SUMMARY → GLOBAL_REVIEW → RESULT_REVIEW
                        → (循环) → END_PLUGINS → COMPLETED
```

### 9.4 工作目录结构

```
runs/{run_name}/run/vuln_scan_{task_id}/
├── input/task.md                       ← 自动生成的任务描述
├── working/                            ← Worker 工作目录
├── results/                            ← 漏洞报告 (result_NNN.md)
├── supporting_docs/                    ← 辅助分析文档
├── reviews/cycle_N/                    ← 评审记录
├── output/final_output/                ← 最终交付件
│   ├── summary.md
│   ├── results/ (confirmed/ / false_positive/ / pending_review/)
│   └── index.json
├── _meta/
│   ├── state.json                      ← 工作流状态
│   ├── vulnerability_list.json         ← 漏洞状态清单
│   ├── review_summaries/cycle_*.json   ← 评审摘要
│   ├── cycle_metrics/cycle_*.json      ← 每轮指标
│   ├── checkpoints/cycle_N_*.json      ← step 级断点
│   ├── result_relations.json           ← 结果文件关系
│   ├── results_manifest.json           ← 结果文件清单
│   └── resume_preview.json             ← 续跑预览
├── sessions/                           ← Agent 对话历史
└── run/
    ├── config.json                     ← 实际使用配置
    └── _meta/run_timestamps.json       ← 运行时间戳
```

## 10. 服务架构

### 10.1 三角色部署

| 角色 | 职责 |
|:---|:---|
| **api** | REST API + 任务 CRUD + 服务注册 + Vuln Report 提交 |
| **manager** | 任务调度 + 状态流转 + LLM Provider 同步 + 心跳监控 + 卡死回收 |
| **worker** | 任务消费 + 子进程执行 + Agent 调用 + 进度上报 |

三角色通过 `scheduler.role` 配置切换（`standalone` 三合一，`api` / `manager` / `worker` 分离部署）。

**Worker 单槽执行模型**（`execution_service.py` 强制约束）：
- 每个 worker Pod 同时只运行一个 `run_vuln_scan.py` 子进程
- 任务启动前自动清理残留 pi Agent 进程，完成后再次清理
- 多任务并发通过水平扩展 worker Pod 实现
- Worker 容量通过 `scheduler.worker_capacity` 配置（默认 1）

**调度器核心机制**：
- **Slot 预留**：`SchedulerWorkerSlotReservation` DB 表实现租约
- **退避 (Backoff)**：启动失败后延迟重试（initial 10s, max 60s）
- **Grace 期保护**：worker 启动后短暂保护，防止误判卡死
- **心跳监控**：每 2s 上报心跳，超时 300s 后回收
- **Drain 优雅退出**：preStop hook，最多等待 45s

### 10.2 Agent 状态目录

| 任务用途 | root_dir | 说明 |
|:---|:---|:---|
| `normal` | `/data/files/{project}/DATAFLOW_VULN_SCANNER/agent-state/shared/{agent_id}` | 共享 skills/memory |
| `evolution` | 自定义 `root_dir` | 独立目录，用于 Prompt 进化实验 |

### 10.3 外部依赖

| 服务 | 用途 |
|:---|:---|
| MySQL | 任务状态、运行记录、事件持久化、worker slot 预留 |
| Nacos | 服务注册与发现 |
| LLM Provider API | AI 模型推理（通过 pi RPC 客户端） |
| NFS PVC (`/data`) | 共享文件系统（源码、输出、session） |
| Harbor | Docker 镜像仓库 |

## 11. 断点续跑 (Resume)

### 11.1 Cycle 级恢复

`resume.py` 的 `build_resume_plan()` 分析工作目录状态：识别已完成 cycle 数、恢复 session ID、计算剩余 cycle 配额、重新加载并应用 profile 策略。

### 11.2 节点级恢复 (Step Checkpoint)

`checkpoint.py` 提供 step 级 checkpoint，每个 workflow step 完成后落盘。Resume 时跳过已完成节点。状态：`completed` / `partial_salvaged` / `timeout_detected` / `failed`。仅支持单阶段 atomic 工作流。

## 12. Prompt 体系

### 12.1 vuln_scan Prompts（14 个文件）

| Prompt 文件 | 使用者 | 用途 |
|:---|:---|:---|
| `worker_system.md` | pi-worker | 核心身份定义 |
| `worker_user.md` | pi-worker | 初始任务指令（cycle=1, discovery） |
| `worker_profile_driven_exploration.md` | pi-worker | Profile 驱动深度探索（rework stage 1） |
| `worker_rework_missed_hunt.md` | pi-worker | 遗漏漏洞追猎（rework stage 2） |
| `worker_audit_appendix.md` | pi-worker | 审计附录指引 |
| `reflect_completeness.md` | pi-worker | 自我反思主 prompt |
| `reflect_checklist_initial.md` | pi-worker | 首轮反思 checklist |
| `reflect_checklist_rework.md` | pi-worker | Rework 轮反思 checklist |
| `reflect_checklist_result_repair.md` | pi-worker | 结果修复反思 checklist |
| `summary.md` | pi-worker | 总结模板 |
| `global_review_completeness_user.md` | pi-advisor | 全面性审计（score: coverage） |
| `global_review_depth_user.md` | pi-advisor | 深入性审计（score: vuln_pattern_breadth） |
| `result_review_sys.md` | pi-advisor | 误报检测系统提示词 |
| `result_review_user.md` | pi-advisor | 逐报告误报验证 |

### 12.2 Pipeline Prompts（full_vuln_pipeline 场景）

```
prompts/pipeline/
├── unpack_analysis/          ← 解包分析
├── system_analysis/          ← 系统分析
├── decompile_optimize/       ← 反编译优化
├── external_entry_analysis/  ← 外部入口分析
├── data_flow_analysis/       ← 数据流分析
└── docker_system.md          ← Docker 执行环境系统提示
```

## 13. 一键启动器 (run_vuln_scan.py)

```
run_vuln_scan.py --data-flow /path/to/dataflow/ --source-dir /path/to/src/

  1. 扫描数据流目录 → 发现 dataflow/*.md
  2. 扫描源码目录 → 枚举 .c/.h/.cc/.cpp/.hpp/.asm/.s
  3. 生成 task.md → 注入函数范围、数据流标记、源码清单
  4. 生成 config.json → 合并默认配置 + CLI 参数 + Profile 策略
  5. 调用 CompositeWorkflowEngine.run()
  6. 监控进度 + 收集最终产物
```

支持 `--resume` 从断点续跑，`--profile` 指定评审策略，`--model` 指定 LLM 模型。

## 14. Dashboard

基于 **FastAPI** 的 Web Dashboard（`dashboard/server.py`），前端为 `dashboard/static/` 中的 HTML/JS/CSS。启动：`python run_dashboard.py [--port 8501] [--runs-dir runs/]`。展示运行状态、任务进度、评分趋势、结果浏览。

## 15. 与 SecFlow 流水线的集成

dataflow-vuln-scanner 是 binary-security 端到端流水线的最后一个阶段：

```
binary-security (总编排)
    │
    ▼
firmware-unpacker → system-analyse → binary-to-source (可选)
    → entry-analyse → dataflow-analyse → dataflow-vuln-scanner
```

**上游输入契约**（来自 dataflow-analyse）：
- `final_report.md`：根函数 + 调用链 + 数据流标记（INPUT/DIRECT_SINK/USED/EXPORT/CLEANED/★）
- `dataflow/*.md`：每个被跟踪函数的详细污点分析
- 源码目录：`.c/.h/.cc/.cpp/.hpp/.asm/.s` 文件或 `files.list`

## 16. 设计原则

| # | 原则 |
|:---|:---|
| 1 | **配置定义行为，框架只做调度** — 智能体、工作流、角色、评审策略、插件链全部 JSON 外置 |
| 2 | **三级评审闭环，独立验证** — 每一级评审者拥有独立上下文，不做 Worker 的延伸 |
| 3 | **证伪优于证实** — 结果评审员目标是寻找漏洞不存在的证据 |
| 4 | **Worker 有状态，Advisor 无状态** — Worker 跨轮复用 session，Advisor 每轮全新上下文 |
| 5 | **插件链编排，6 种返回码控制流** — 插件通过返回码控制阶段流转 |
| 6 | **Plateau 检测，自动止损** — 多维指标（scores、产物指纹、新增结果）判定停滞，自动 closure 或 abort |
| 7 | **多 Agent 运行时适配** — 4 种运行时通过统一 AgentRuntime 接口切换 |
| 8 | **断点续跑，节点级恢复** — cycle 级 + step 级 checkpoint，支持 partial_salvaged |
| 9 | **数据流主轴优先** — Worker 以数据流标记为主轴，不做脱离数据流的全项目重扫 |
| 10 | **Profile 驱动深度** — fast/balanced/audit 三档统一控制评审深度、Worker 预算、证据要求 |
| 11 | **指纹追踪防重审** — 已通过结果文件 SHA256 指纹未变则跳过重审 |
| 12 | **Rework 双阶段路由** — profile 探索 + missed hunt，由路由状态动态决定执行 |

## 17. 性能参考

| 场景 | 数据流文件数 | Review Cycles | 耗时 |
|:---|:---|:---|:---|
| 简单单函数 | 1-3 | 2-3 | 10-30 min |
| 中等模块 | 5-10 | 3-5 | 30-90 min |
| 复杂模块 | 10-30 | 4-6 | 1-4 h |

