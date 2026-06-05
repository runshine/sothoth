# dataflow-analyse 架构设计

## 1. 定位

dataflow-analyse 是 SecFlow 分析流水线中的 **C/C++ 数据流污点分析系统**。它接收入口函数（由上游 entry-analyse 产出）及其污点参数，通过 **多 Worker + 多 Judge 循环 + BFS 递归调用链追踪**，逐函数分析外部数据在调用链中的传播路径，产出可直接交付的跨函数数据流分析报告。

系统不自行发现入口——它依赖上游 entry-analyse 提供的结构化入口清单。它的职责是**从一条已知入口出发，沿着函数调用图追踪污点的每一步传递**，直到抵达叶子函数或达到配置的深度上限。

## 2. 挑战

C/C++ 数据流分析面临三个核心矛盾：

**深度与精度的矛盾。** 一个典型的网络协议模块（如 OpenThread Commissioner）入口函数可能调用 5-15 个下游函数，每个下游又调用 3-8 个更深层函数，形成深度 3-5 层的调用树。让 LLM Agent 逐函数分析时，每个函数需要约 2-8 分钟的 LLM 交互（tool call + 推理），一棵深度 3 的调用树意味着数十至上百次 LLM 调用。系统需要一种方式在"逐层追踪的完整性"和"批量并行的效率"之间取得平衡。

**参数级隔离与函数级合并的矛盾。** 一个入口函数（如 `HandleCommissioningSet`）可能有 3-5 个污点参数（`aHeader`, `aMessage`, `aMessageInfo` 等），每个参数有独立的传播路径。拆分到参数级分析可以提升每个参数的追踪精度，但最终需要将分散的分析结果合并为函数级报告——且合并时不能丢失跨参数的交互（如某个参数的派生值被注入到另一个参数指向的对象中）。

**LLM 可靠性与交付质量的矛盾。** LLM 在分析超过 200 行的函数时容易出现遗漏（未覆盖全部使用点）或幻觉（编造不存在的调用关系）。单次 LLM 输出的质量波动大，需要一个验证闭环来拦截并修复低质量输出。

dataflow-analyse 的解法是 **"PerTaintWorkflow 参数级并行 + Judge 评审闭环 + BFS 工作池递归"三层共振**：用多 session 并行实现参数级隔离分析，用 Judge 独立校验过滤低质量输出，用 BFS 队列 + Worker Pool 实现调用树的广度优先并发展开。

## 3. 核心能力

系统回答三个问题：

| | 问题 | 方式 |
|:---|:---|:---|
| ① | 外部数据进入当前函数后，经过了哪些代码路径？ | PerTaintWorkflow：对每个污点参数独立追踪，标记 🔴 TAINTED 派生变量，识别 DIRECT_SINK（如 memcpy 危险调用） |
| ② | 污点数据传递给了哪些下游函数？ | 从每个污点的传播路径中提取子函数调用表（callee + 调用位置 + 接收的形参），汇总为 tainted.list |
| ③ | 下游函数内部，污点数据又如何传播？ | BFS 递归：对 tainted.list 中的每个 callee，启动新一轮 Worker+Judge 分析，直到深度上限或叶子函数 |

## 4. 总体架构

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    SecFlow 平台 (前端 / API Gateway)                       │
│                    /api/app/dataflow-analyse                             │
└────────────────────────────┬─────────────────────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────────────────────┐
│              dataflow-analyse 服务 (FastAPI, Python)                      │
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────┐    │
│  │   API Layer      │  │   Task Service   │  │  Worker Execution  │    │
│  │   server.py       │  │                   │  │                    │    │
│  │                   │  │  • Task CRUD      │  │  • 租约争抢        │    │
│  │  • POST /tasks    │  │  • 状态流转       │  │  • 并发控制        │    │
│  │  • GET /tasks     │  │  • 审核回调       │  │  • 心跳续租        │    │
│  │  • SSE /stream    │  │  • 事件持久化     │  │  • 卡死检测        │    │
│  │  • Health/Ready   │  │  • 审核队列轮询   │  │  • 断点续跑        │    │
│  └────────┬─────────┘  └────────┬─────────┘  └─────────┬──────────┘    │
│           │                     │                      │                │
│           │         ┌───────────┴──────────────────────┘                │
│           │         │                                                   │
│           ▼         ▼                                                   │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    编排引擎 (orchestrator.py)                      │  │
│  │                                                                   │  │
│  │  execute_recursive(depth=0)  ← BFS 队列 + Worker Pool             │  │
│  │                                                                   │  │
│  │  ┌─────────────────────────────────────────────────────────────┐ │  │
│  │  │  PerTaintWorkflow (taint_workflow.py)                       │ │  │
│  │  │                                                             │ │  │
│  │  │  Phase 1: base_session      — 阅读函数源码                  │ │  │
│  │  │     └─ fork ──┬─ taint_session[param1]  — 深入分析单个污点  │ │  │
│  │  │               ├─ taint_session[param2]                      │ │  │
│  │  │               ├─ ...                                        │ │  │
│  │  │               └─ summary_session        — 汇总 → 最终报告   │ │  │
│  │  │                                                             │ │  │
│  │  │  Phase 2: 并行执行所有 taint_sessions (受 worker_count 限速) │ │  │
│  │  │  Phase 3: summary_session 读取所有 taint-flow 文件合并       │ │  │
│  │  │  Phase 4: Judge 独立评审 → 路由反馈到对应 session 重新分析   │ │  │
│  │  └─────────────────────────────────────────────────────────────┘ │  │
│  │                                                                   │  │
│  │  通过后:                                                          │  │
│  │    • 解析 tainted.list → BFS 队列入队                            │  │
│  │    • cpp_resolver 预检: 函数定义存在？非 stdlib？                 │  │
│  │    • 过滤自引用 / 已分析 / 无定义 → 入队执行                      │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                   跨切面设施                                       │  │
│  │  • runner.py          — pi RPC 进程管理 + 双层重试                  │  │
│  │  • prompt_builder.py  — 动态 Worker/Judge/Eval/Summary Prompt 构造 │  │
│  │  • parsers.py         — callee 列表、评审结果、tainted.list 解析   │  │
│  │  • cpp_resolver.py    — C++ 符号定位、函数定义发现                 │  │
│  │  • metrics.py         — 可观测性指标采集                          │  │
│  │  • probe_server.py    — 独立健康探针端口 (18080)                   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

## 5. 核心编排名录

### 5.1 执行层：PerTaintWorkflow — 参数级并行污点分析

PerTaintWorkflow 是单函数分析的核心工作流。它将一次"W+J"循环解耦为四个阶段，实现参数级隔离与函数级汇总的统一。

```
PerTaintWorkflow.run()  ← 主循环 (1..max_rounds)

  每轮:
    Phase 2: asyncio.gather(taint_session[param1], taint_session[param2], ...)
             受 Semaphore(worker_count) 限速
             每个 taint_session:
               - 使用独立 session 文件 (fork 自 base_session)
               - 接收上游 taint_hint (来自 entry-analyse)
               - 接收 extract_func 预提取的函数体（含绝对行号 L{n} 前缀）
               - 禁止 read/bash 工具调用（函数体已注入 prompt，无需 tool call）
               - 产出: taint-flow-{param}.md（单污点完整传播路径 + 子函数表）

    Phase 3: summary_session ← 读取所有 taint-flow-*.md
              产出: dataflow-{func}.md + tainted.list + taintvars.json

    Phase 4: Judge (独立上下文，只读工具) ← 评审汇总报告
             解析评审结果:
               - 通过 (score ≥ 阈值) → 返回成功
               - 不通过 → 路由反馈到对应 session
                 [TAINT:param1,param2] → 重新注入 taint_session
                 [SUMMARY] → 重新注入 summary_session
```

**设计决策 — 为什么不在 Phase 1 运行 base_session？**
原始设计中 Phase 1 会启动一个 base_session 让 Worker 阅读源码，然后 fork 到各 taint_session。但实践中发现 extract_func 可以在 Python 端高效提取函数体（毫秒级），直接将完整代码注入 taint prompt 能消除每次分析的"阅读源码"tool call（节省 30-90s），且代码行号 L{n} 前缀保证了 LLM 使用正确的行号引用。因此当前实现中 base_session 未被实际使用，函数体由 orchestrator 侧一次性提取。

**设计决策 — 为什么每个 taint 用独立 session？**
单个 session 内分析多个污点参数时，LLM 容易在参数间混淆（将 param1 的追踪嵌入到 param2 的报告中），且上下文窗口被大量中间推理占用。独立 session 保证每个污点的分析是隔离的、可独立重试的，Judge 反馈也能精准路由到出问题的参数 session。

### 5.2 递归层：BFS 队列 + Worker Pool

```
                     根函数 A (depth=0)
                         │
              ┌──────────┼──────────┐
              │          │          │
           callee_B   callee_C   callee_D
         (depth=1)  (depth=1)  (depth=1)
              │          │
         ┌────┼────┐    ...
         │    │    │
        E    F    G
    (depth=2)
```

**BFS 架构要点**：

| 机制 | 实现 |
|:---|:---|
| **队列** | `asyncio.Queue()` — 无界先进先出 |
| **工作池** | `n_workers` 个 `asyncio.create_task(worker(i))` 协程，并发处理队列项 |
| **并发控制** | `callee_concurrency` 决定工作池大小（默认 4，1 = 串行，-1 = 自动 4） |
| **去重** | 全局 `analyzed: set[str]` 防止环路导致的重复分析 |
| **深度限制** | `max_trace_depth`（默认 3），达到上限时 callee 表格仍填写但系统不再递归 |
| **终止 sentinel** | `queue.join()` 后，向每个 worker 发送 `None` 通知退出 |

**callee 入队前的预检链**（避免无效分析）：
```
tainted.list / dataflow 解析
  → 去自引用（callee == 当前函数）
  → 去已分析 (analyzed set 查重)
  → 去标准库 (_STDLIB_SKIP 黑名单: memcpy/malloc/strlen 等 40+ 函数)
  → cpp_resolver 验证函数定义存在 (_function_has_definition)
  → 构建 sub_cfg (CalleeRef → TaskConfig)
  → 入队
```

### 5.3 合并层：程序化 + LLM 双重合并

递归分析完成后，所有子函数的 `dataflow-{func}.md` 文件存放在 `run/dataflow/` 目录下。系统采用双重合并策略：

```
1. 程序化合并 (_build_combined_report)
   - 按深度排序所有 dataflow 文件
   - 生成调用树结构（根 → 子 → 孙）
   - 追加每个函数的分析内容
   - ★ 始终成功，保证有可交付产物

2. LLM merge agent（可选增强）
   - 调用独立的 merge agent（prompts/merge/default.md）
   - 将分散的 dataflow 文档合并为单一连贯报告
   - 仅在 LLM 产出显著更丰富时替换程序化结果
   - 失败时保留程序化报告，不阻断流程
```

## 6. Judge 评审闭环

### 6.1 经典 Orchestrator 模式 (execute)

用于顶层入口函数的单函数分析，支持多 Worker × 多 Judge 的矩阵评审。

```
┌──────────────────────────────────────┐
│        W+J 轮次循环                   │
│                                      │
│  Workers[0..W-1] 并行分析             │
│    ↓                                 │
│  Judges[0..J-1] 并行评审              │
│    ↓                                 │
│  投票统计 (pass_count >= pass_threshold)
│    ↓                                 │
│  ┌─ pass & round ≥ min_rounds → ✅ 通过  │
│  │  pass & round < min_rounds →  强制反思 │
│  │  fail → 生成 feedback → 下一轮        │
│  │  达到 max_rounds → 按策略终止         │
│  └────────────────────────────────── │
└──────────────────────────────────────┘
```

**Judge 评审维度**：

| 维度 | 分值 | 说明 |
|:---|:---|:---|
| F1 | 强制 | 报告文件存在且有内容 |
| F2 | 强制 | 报告包含正确的函数名 |
| 外部输入识别 | 20分 | 入口参数描述准确 |
| 污点追踪完整性 | 35分 | 当前函数内所有使用点覆盖 |
| 子函数识别 | 25分 | tainted.list 准确无误 |
| 文档规范 | 20分 | 🔴 标记、树状图、行号规范 |

Judge 通过后，系统从 Voting 中选出最佳 Worker 的输出（多数票决定 `best_worker_id`）作为最终结果。

### 6.2 PerTaintWorkflow 的单 Judge 模式

用于递归子函数分析时，采用单 Worker + 单 Judge 的简化模式。Judge 评审汇总报告（`dataflow-{func}.md`），通过路由机制将反馈精准分发到出问题的 taint session 或 summary session。

**反馈路由**：
```
Judge 改进指令中的标签:
  [TAINT:param1,param2] → taint_feedbacks[param1] += feedback
                          taint_feedbacks[param2] += feedback
  [SUMMARY]             → summary_feedback += feedback

无显式标签时: 任意参数名命中 → 路由到对应 taint + summary (全量路由)
```

## 7. 数据模型

### 7.1 核心配置

```
ServiceConfig (config.json, 管理员一次性配置)
│
├── workers / judges (RoleConfig)
│   ├── default_model / default_tools / default_thinking_level
│   ├── system_prompt_dir
│   └── agents: [AgentInstanceConfig]
│       └── model / tools / system_prompt / thinking_level
│
└── 执行控制
    ├── max_rounds (-1=无限) / min_rounds (强制至少轮数)
    ├── pass_threshold (all / majority / 数字)
    ├── max_trace_depth (递归深度上限)
    └── callee_concurrency (BFS 工作池大小)

TaskConfig (ServiceConfig + 用户输入, 运行时合成)
│
├── 用户输入: task / source_file / function_name / line_hint
├── 上游注入: taint_params / function_description / entry_reason / taint_details
└── 继承 ServiceConfig 的所有执行参数
```

### 7.2 执行结果

```
TaskResult
├── task_id / status (PASSED/FAILED/ERROR/...)
├── rounds: [RoundResult]
│   ├── worker_results: [WorkerResult]
│   │   └── output / dataflow_file / session_file / token_usage / df_issues
│   └── judge_results: [JudgeRoundResult]
│       ├── evaluations: [WorkerEvaluation]
│       └── summary: JudgeSummary
├── final_output (合并后的最终数据流报告)
├── total_duration_ms / total_tokens
└── completion_reason
```

### 7.3 调用链引用

```
CalleeRef (从 Worker 输出中解析)
├── function_name (被调用函数全名, 如 "Class::Method")
├── file (源文件路径)
├── line (调用点行号, 如 "L228")
├── tainted_params (接收的形参列表)
└── description (调用上下文简述)
```

## 8. Agent 运行时

### 8.1 pi RPC 进程管理 (runner.py)

```
pi --mode rpc --session <session_file> [--model <model>]
       ↑ stdin:  {"type":"prompt","message":"..."}
       ↓ stdout: JSONL events (message_end / stream_delta 等)

双层重试机制:
┌─────────────────────────────────────────────────────┐
│ 外层 — 进程级重试 (pi_max_retries, 默认 3)          │
│   进程拉起失败 / 崩溃 / SIGKILL → 重新拉起           │
│   致命错误: 401 Unauthorized / model not found       │
│   → 不重试，PiFatalError 终止流水线                  │
├─────────────────────────────────────────────────────┤
│ 内层 — API 级重试 (agent_max_retries, 默认 100)     │
│   连接超时 / 限流 429 / 服务错误 5xx → 重试           │
│   固定退避: 3s → 5s → 10s → 15s → 30s (上限 30s)    │
│   502 特殊处理: 等待更长时间（模型过载信号）          │
└─────────────────────────────────────────────────────┘

超时管理: agent_run_timeout_seconds (默认 3600s)
超时后行为: timeout_retry_enabled=true → 自动重新输入并继续 (最多 timeout_max_retries 次)

卡死检测: 1800s 无 message_end → 检测 + 重启 (5次上限)
```

### 8.2 Session 管理

| Session 类型 | 持久化 | 跨轮行为 | 说明 |
|:---|:---|:---|:---|
| Worker session | `worker-{i}.jsonl` | 复用，保留上下文 | 跨轮保持，feedback 注入后继续分析 |
| Judge session | 每轮新建 `judge-{i}-round-{rnd}.jsonl` | 不跨轮 | 独立上下文，保证评审无偏 |
| Taint session | `worker-0-taint-{param}.jsonl` | 跨轮复用 | fork 自 base，接收针对性 feedback |
| Summary session | `worker-0-summary.jsonl` | 跨轮复用 | 汇总合并 session |
| Merge session | 一次性 | 不跨轮 | 仅用于最终报告合并 |

### 8.3 Prompt 构造策略

**Worker Prompts** (prompt_builder.py)：
- 注入上游元数据（function_description、entry_reason、taint_details）
- 注入递归深度上下文（depth/max_depth）
- 注入调用者传入的脏数据上下文（tainted_context）
- 注入结构性问题前置警告（F1/F2/F3 标签——文件未写入/函数名错误等）
- 随机 nonce 前缀（破坏 vllm prefix cache，避免 temperature=0 时的确定性复现）

**Taint Prompts** (taint_workflow.py)：
- 注入 extract_func 预提取的函数体代码（含 L{n} 行号前缀）
- 注入上游 taint_hint（来自 entry-analyse 的污点说明）
- 明确禁止 read/bash 工具调用（函数体已提供）
- 指导 LLM 标记派生变量（🔴 TAINTED）和直接危险操作（⚠️ DIRECT_SINK）

**Judge Prompts**：
- 只读工具（read、bash、find），无 write/edit 权限
- 评分维度表格 + 强制通过项（F1/F2）
- 改进指令路由标签规范（[TAINT:xxx] / [SUMMARY]）

## 9. C++ 符号解析 (cpp_resolver.py)

cpp_resolver 是连接 LLM 输出的函数名与真实源文件的关键桥梁：

| 能力 | 实现 |
|:---|:---|
| `_function_has_definition(target_dir, func_name)` | grep 搜索函数体定义（非纯声明），验证函数是否可分析 |
| `_resolve_cpp_name(target_dir, func_name, hint_file)` | 解析 C++ 限定名（`Class::Method`），定位到具体源文件 |
| `_get_definition_line(target_dir, func_name, hint_file)` | 获取函数定义行号（`L{num}` 格式） |

配合 `_STDLIB_SKIP` 黑名单（40+ 标准库函数如 memcpy/malloc/strlen/printf 等），cpp_resolver 在 callee 入队前完成预检过滤，避免对标准库函数和纯声明函数启动完整的 W+J 流水线。

## 10. 服务架构与部署

### 10.1 运行时角色

dataflow-analyse 在 Kubernetes 中以双角色部署，通过 `DFA_ROLE` 环境变量控制：

| 角色 | Deployment | Replicas | 职责 |
|:---|:---|:---|:---|
| **api** | `secflow-app-dataflow-analyse` | 2 | REST API + 任务创建/查询 + SSE 事件流 + 服务注册 |
| **worker** | `secflow-app-dataflow-analyse-worker` | 6 | 任务争抢（租约）+ 编排执行 + 心跳续租 + 卡死检测 |

**api Pod**：
- `DFA_ENABLE_PUBLIC_API=true` — 对外暴露 REST 接口
- `DFA_ENABLE_DISPATCHER=false` — 不执行任务
- `DFA_ENABLE_EXECUTOR=false` — 不运行编排引擎
- 资源: 2 CPU / 4 GiB

**worker Pod**：
- `DFA_ENABLE_EXECUTOR=true` — 运行编排引擎
- `DFA_ENABLE_DISPATCHER=true` — 主动争抢任务队列
- `DFA_MAX_LOCAL_RUNNING_TASKS=4` — 单 Pod 最多并发 4 个分析任务
- `DFA_LEASE_TTL_SECONDS=300` — 任务租约 5 分钟
- `DFA_HEARTBEAT_INTERVAL_SECONDS=60` — 心跳间隔 1 分钟
- 资源: 6 CPU / 12 GiB (request), 8 CPU / 16 GiB (limit)

### 10.2 任务分发 (Dispatcher)

worker Pod 通过 Dispatcher 主动从数据库拉取任务：

```
dispatch_loop (每 3s)
  ├── 查询 status=pending 的任务
  ├── 按优先级 + FIFO 排序
  ├── 尝试抢占任务租约 (UPDATE lease_worker_id + lease_until)
  ├── 本地 running_tasks < DFA_MAX_LOCAL_RUNNING_TASKS → 接受
  └── 提交到 asyncio.Task 执行 orchestator.execute_recursive()

心跳续租 (每 60s)
  └── UPDATE lease_until = now() + DFA_LEASE_TTL_SECONDS

卡死检测
  └── 扫描 lease_until 过期的 running 任务 → 回收 (status 改回 pending)
```

### 10.3 外部依赖

| 服务 | 用途 |
|:---|:---|
| MySQL | 任务状态、事件持久化、配置存储、审核队列 |
| Nacos | 服务注册与 LLM Provider 配置同步 |
| NFS PVC (`/data`) | 共享文件系统（源码、输出、session 文件） |
| Harbor | Docker 镜像仓库 |

### 10.4 部署清单

```
13-secflow-service/
├── 00-secflow-105-00-app-dataflow-analyse-configmap.yaml     ← 服务配置
├── 00-secflow-105-01-app-dataflow-analyse-deployment.yaml    ← API (replicas: 2)
├── 00-secflow-105-02-app-dataflow-analyse-service.yaml       ← ClusterIP Service
├── 00-secflow-105-03-app-dataflow-analyse-worker-deployment.yaml ← Worker (replicas: 6)
├── 00-secflow-105-04-app-dataflow-analyse-hpa.yaml           ← API HPA
├── 00-secflow-105-05-app-dataflow-analyse-worker-hpa.yaml    ← Worker HPA
```

## 11. 与 SecFlow 流水线的集成

dataflow-analyse 是 binary-security 端到端流水线的第四个阶段：

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
entry-analyse (入口函数发现)     ← 输出 functions.list
    │
    ▼
dataflow-analyse (污点传播追踪)  ← 本节所述
    │ 输入: functions.list + source_root_path
    │ 产物: dataflow/ 目录 + final_report.md
    ▼
dataflow-vuln-scan (漏洞挖掘)
```

**上游输入契约**（来自 entry-analyse）：
```
TaskConfig
├── source_file          ← 相对 source_root_path 的文件路径
├── function_name        ← 待分析函数名
├── line_hint            ← 函数起始行号（如 "L228"）
├── taint_params         ← ["aHeader", "aMessage", "aMessageInfo"]
├── function_description ← entry-analyse 给出的函数用途
├── entry_reason         ← entry-analyse 给出的入口判定原因
└── taint_details        ← 逐污点描述: [{name, description, source_kind, description_source}]
```

**下游输出**（供 dataflow-vuln-scan 消费）：
```
output/
├── flag                         ← 1=成功 / 0=失败
├── final_report.md              ← 合并后的完整跨函数数据流报告
└── dataflow/                    ← 逐函数分析文件
    ├── HandleCommissioningSet.md
    ├── SetCommissioningData.md
    └── SendCommissioningSetResponse.md
```

## 12. 目录结构

```
{output_dir}/{task_id}/
├── output/                      ← 最终交付件
│   ├── flag                    ← 1=成功 / 0=失败
│   ├── final_report.md         ← 合并后的跨函数数据流报告
│   └── dataflow/               ← 逐函数分析文件
│       └── <FuncName>.md
│
├── run/                         ← 运行时产物
│   ├── report.md               ← 分析摘要报告
│   ├── result.json             ← 结构化结果
│   ├── sessions/               ← Agent session 文件
│   │   ├── worker-0-base.jsonl
│   │   ├── worker-0-taint-{param}.jsonl
│   │   └── worker-0-summary.jsonl
│   ├── dataflow/               ← 子函数数据流文件
│   │   └── <FuncName>.md
│   ├── round_001/              ← 每轮归档
│   │   ├── workers/
│   │   │   ├── worker-0-output.md
│   │   │   └── worker-0-dataflow.md
│   │   ├── judges/
│   │   │   └── judge-0/
│   │   │       └── eval-worker-0.md
│   │   └── feedback.md
│   ├── workspace-worker-0/     ← Worker 工作目录
│   │   ├── [源文件符号链接]
│   │   ├── taint-flow-{param}.md
│   │   ├── tainted.list
│   │   └── taintvars.json
│   └── subtasks/               ← 递归子函数中间产物
│       └── depth_01/
│           └── {tid}-{FuncName}/
│               ├── round_001/
│               └── sessions/
│
└── events/                      ← 任务事件流
```

## 13. 配置参考

### 关键参数

| 参数 | 默认值 | 说明 |
|:---|:---|:---|
| `max_rounds` | -1 (∞) | 每函数最大 W+J 轮数。Judge 不通过则无限重试 |
| `min_rounds` | 1 | 最少轮数——即使第 1 轮通过也继续反思 |
| `pass_threshold` | majority | Judge 通过策略。all = 全部通过, majority = ceil(J/2) |
| `max_trace_depth` | 3 | 调用链递归最大深度 |
| `callee_concurrency` | 4 | BFS 工作池并发数（1=串行追踪, -1=自动 4） |
| `worker_count` | 1 | 单函数内并行 Worker 数（经典模式） |
| `judge_count` | 1 | 单函数内并行 Judge 数 |
| `agent_max_retries` | 100 | API 级错误重试上限 |
| `agent_run_timeout_seconds` | 3600 | 单次 Agent run 超时（秒） |
| `pi_max_retries` | 3 | pi 进程崩溃重试上限 |

### LLM Provider 配置

```json
{
  "models": [
    {
      "name": "icsl_vllm_2/MiniMax/MiniMax-M2.5",
      "provider": "openai-completions",
      "baseUrl": "http://172.31.23.100:8002/v1",
      "model": "MiniMax/MiniMax-M2.5"
    }
  ]
}
```

Worker 和 Judge 可使用不同模型，也可使用同一模型的不同实例。

## 14. 设计原则

| # | 原则 |
|:---|:---|
| 1 | **参数级隔离，函数级汇总** — 每个污点参数独立 session 分析（避免参数混淆 + 支持精准反馈路由），summary session 负责合并为函数级报告 |
| 2 | **预注入消除 tool call** — extract_func 在 Python 端预提取函数体（含绝对行号），注入 taint prompt，将每次分析从 "read 文件 → grep → read" 的多次 tool call 降至零次 |
| 3 | **Judge 独立校验，拦截低质量输出** — Judge 无 session 记忆、只读工具、每轮全新上下文；反馈路由机制精准将改进指令分发到对应的 taint/summary session |
| 4 | **BFS 广度优先，工作池并发** — 兄弟 callee 并发分析（asyncio.gather），callee_concurrency 控制工作池大小；深度逐层展开，保证横向扩展的吞吐 |
| 5 | **预检过滤，避免无效 W+J** — cpp_resolver 验证函数定义 + _STDLIB_SKIP 黑名单过滤 + analyzed set 去重，在启动昂贵的 LLM 流水线前完成确定性预检 |
| 6 | **程序化合并兜底，LLM 增强可选** — 递归分析完成后先程序化合并（按深度排序 + 调用树构造），LLM merge agent 仅做增强；合并失败不阻断交付 |
| 7 | **无上限轮次，质量驱动停止** — max_rounds=-1 时 Judge 不通过则无限重试，通过才停止；配合 min_rounds 保证至少一轮自我反思 |
| 8 | **Session 复用，上下文继承** — Worker/taint/summary session 跨轮复用，Judge session 每轮独立；避免 LLM 在评审时受此前分析上下文的污染 |
| 9 | **租约驱动的分布式执行** — Worker Pod 通过 DB 租约争抢任务，心跳续租，卡死检测自动回收；多 Pod 零协调、无单点 |
| 10 | **可追溯** — 每轮 W+J 输出、session 对话历史、dataflow 中间文件均持久化到磁盘和 MySQL，支持复盘和审计 |

## 15. 与 dataflow-vuln-scan 的关系

dataflow-analyse 与 dataflow-vuln-scan 是 SecFlow 流水线中的上下游服务，共享相同的编排架构（Orchestrator + Worker/Judge + BFS 递归），但职责不同：

| 维度 | dataflow-analyse | dataflow-vuln-scan |
|:---|:---|:---|
| **定位** | 污点传播路径追踪 | 漏洞模式识别与验证 |
| **输入** | entry-analyse 的 functions.list | dataflow-analyse 的 dataflow/ 输出 |
| **Prompt 策略** | 聚焦"外部数据经过了哪些代码路径" | 聚焦"这些路径上是否存在安全漏洞" |
| **特有组件** | PerTaintWorkflow（参数级隔离） | vuln_workflow（漏洞挖掘流程）、vuln_store（漏洞持久化）、vuln_graph_service（漏洞图谱） |
| **Skill** | write-dataflow、write-taint-flow | mine-dataflow-vulnerability、write-taint-graph |

## 16. 性能参考

| 场景 | 函数数 | 深度 | 每函数耗时 | 总耗时 |
|:---|:---|:---|:---|:---|
| 单入口浅调用链 | 1-3 | 1 | 2-5 min | 2-15 min |
| 中等复杂度模块 | 5-12 | 2-3 | 3-8 min | 20-60 min |
| 大型复杂模块 | 15-40 | 3-4 | 3-10 min | 1-3 h |

> 每函数耗时取决于代码行数（100-500 行）和 LLM Provider 并发能力。预注入函数体 + 零 tool call 优化将单函数分析时间压缩了 40-60%（相比传统"read+grep+分析"的多次 tool call 模式）。

---
> 文档版本：`v2.1` @ `5e4b6467` · 子模块 `740abbd`（2026-06-05）
