# dataflow-vuln-scan 架构设计

## 1. 定位

dataflow-vuln-scan 是 SecFlow 分析流水线中的 **数据流漏洞挖掘系统**。它接收上游 dataflow-analyse 产出的逐函数污点传播路径，在调用链的每一层执行 **污点图谱抽取 → 漏洞模式识别 → 跨函数跟入** 的闭环分析，产出结构化的漏洞发现清单和可视化污点传播图谱。

系统是新一代架构，取代了此前的 JSON 配置驱动扫描器（`dataflow-vuln-scanner`，legacy）。与旧版相比，新架构的核心突破在于：将"漏洞挖掘"从"事后分析"升级为"分析过程中的结构化副产品"——每个函数的污点分析同时产出图谱数据库记录，漏洞判断在 fork session 中独立完成，不污染主分析上下文。

## 2. 挑战

漏洞挖掘面临三个核心矛盾：

**分析深度与漏洞发现时机的矛盾。** 传统流程中，漏洞挖掘在全部数据流分析完成后进行——此时分析者面对数十份 dataflow 文档，必须手动回溯长调用链中的每个传播节点，容易遗漏跨函数的安全问题。理想的方式是"边分析边挖掘"：在每层函数的污点分析完成后立即判断当前函数内是否存在漏洞候选。

**图谱完备性与 LLM 上下文限制的矛盾。** 一个深度 3 的调用树（30+ 函数）产生的污点传播图包含数百个节点和边。让 LLM 在一次 prompt 中理解全局图谱并做漏洞判断是不可行的。需要将图谱持久化到确定性存储（SQLite），让 LLM 只对当前函数的局部子图做判断。

**多跟入点的上下文爆炸。** 当函数 A 将污点数据传给 B、C、D 三个子函数时，B/C/D 各自的分析是独立的。但传统的 Session 复用策略要求所有 callee 从同一个 session fork，导致无关的跟入点信息污染上下文。需要一种按需继承的 fork 策略——每个 callee 只继承其直接调用者的 session，而非整个调用链的历史。

dataflow-vuln-scan 的解法是 **"单 Worker 全域分析 + fork session 独立漏洞挖掘 + SQLite 图谱持久化 + BFS 递归跟入"** 四层架构。通过将图谱定义为确定性数据结构（SQLite schema），将 LLM 的角色从"记忆图谱"转变为"填充图谱"，从而实现图谱与上下文解耦。

## 3. 核心能力

系统回答三个问题：

| | 问题 | 方式 |
|:---|:---|:---|
| ① | 当前函数内，污点数据经过了哪些传播边（赋值、函数调用、返回、字段访问）？ | DataflowVulnWorkflow 单 Worker 全域分析：提取 taint-graph.json（edges + followups + termination） |
| ② | 在当前函数内的这些路径上，是否存在可被利用的安全漏洞？ | fork session（vuln-miners prompt）：从主 worker session 复制上下文，仅判断当前函数内的漏洞模式，不跨函数 |
| ③ | 污点传递给了哪些下游函数？下游函数内部是否也存在漏洞？ | BFS 递归 + session 继承：每个 callee 继承其直接调用者的 worker session，独立分析 + 独立漏洞挖掘 |

## 4. 总体架构

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    SecFlow 平台 (前端 / API Gateway)                       │
│                    /api/app/dataflow-vuln-scan                           │
└────────────────────────────┬─────────────────────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────────────────────┐
│           dataflow-vuln-scan 服务 (FastAPI, Python)                       │
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────┐    │
│  │   API Layer      │  │   Task Service   │  │  Worker Execution  │    │
│  │   server.py       │  │                   │  │                    │    │
│  │                   │  │  • Task CRUD      │  │  • 租约争抢        │    │
│  │  • POST /tasks    │  │  • 状态流转       │  │  • 并发控制        │    │
│  │  • GET /tasks     │  │  • 审核队列       │  │  • 心跳续租        │    │
│  │  • SSE /stream    │  │  • 事件持久化     │  │  • 卡死检测        │    │
│  │  • GET /vuln-graph│  │  • 审核轮询       │  │  • 断点续跑        │    │
│  │  • GET /findings  │  │  • 槽位管理       │  │                    │    │
│  │  • Health/Ready   │  │                   │  │                    │    │
│  └────────┬─────────┘  └────────┬─────────┘  └─────────┬──────────┘    │
│           │                     │                      │                │
│           │         ┌───────────┴──────────────────────┘                │
│           │         │                                                   │
│           ▼         ▼                                                   │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                 编排引擎 (orchestrator.py)                         │  │
│  │                                                                   │  │
│  │  execute_recursive(depth=0)  ← BFS 队列 + Worker Pool             │  │
│  │                                                                   │  │
│  │  ┌─────────────────────────────────────────────────────────────┐ │  │
│  │  │  DataflowVulnWorkflow (vuln_workflow.py)                    │ │  │
│  │  │                                                             │ │  │
│  │  │  Phase 1: 单 Worker 全域分析                                │ │  │
│  │  │    • 提取函数体（extract_func）+ 注入 taint-graph prompt    │ │  │
│  │  │    • Worker 产出:                                           │ │  │
│  │  │      - taint-graph.json  (edges / followups / termination)  │ │  │
│  │  │      - dataflow-{func}.md                                   │ │  │
│  │  │      - tainted.list / taintvars.json                        │ │  │
│  │  │    • 脚本校验 taint-graph.json 结构完整性                     │ │  │
│  │  │                                                             │ │  │
│  │  │  Phase 2: Fork 漏洞挖掘 Session                             │ │  │
│  │  │    • 复制 worker session → vuln-mining session              │ │  │
│  │  │    • 注入 vuln-miners prompt + dataflow 文本                 │ │  │
│  │  │    • 产出: findings JSON → VulnFindingRecord → SQLite       │ │  │
│  │  │    • 每个 finding 独立输出目录:                               │ │  │
│  │  │      output/vulnerabilities/{finding_id}/                   │ │  │
│  │  │        ├── vulnerability-report.md                          │ │  │
│  │  │        ├── taint-path-report.md                             │ │  │
│  │  │        └── context.jsonl                                    │ │  │
│  │  │                                                             │ │  │
│  │  │  Phase 3: 图谱持久化 + Followup 注册                        │ │  │
│  │  │    • edges → taint_edges (SQLite)                           │ │  │
│  │  │    • callees → followups (SQLite, status=pending)           │ │  │
│  │  │    • nodes → taint_nodes (SQLite)                           │ │  │
│  │  └─────────────────────────────────────────────────────────────┘ │  │
│  │                                                                   │  │
│  │  通过后:                                                          │  │
│  │    • 解析 followups 表 → BFS 队列入队                            │  │
│  │    • 多 callee fork: 第一个复用主递归上下文                       │  │
│  │    • 第 2..N 个 callee = 独立 fork session (继承调用者 session)   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                   跨切面设施                                       │  │
│  │  • vuln_store.py           — SQLite 图谱持久化 (6 张表)            │  │
│  │  • vuln_graph_service.py   — 图谱查询与汇总                       │  │
│  │  • vuln_graph_validator.py — taint-graph.json 结构校验            │  │
│  │  • taint_workflow.py       — 共享的基础污点分析逻辑               │  │
│  │  • runner.py               — pi RPC 进程管理 + 双层重试            │  │
│  │  • cpp_resolver.py         — C++ 符号定位、函数定义发现           │  │
│  │  • execution_coordinator.py — 槽位管理 + 执行调度                 │  │
│  │  • session_index.py        — Session 文件索引与归档               │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

## 5. 核心工作流详解

### 5.1 DataflowVulnWorkflow — 单函数三阶段分析

DataflowVulnWorkflow 是 dataflow-vuln-scan 的核心工作流。与 dataflow-analyse 的 PerTaintWorkflow（参数级并行 + summary 合并）不同，它采用 **单 Worker 全域分析** 策略——一个 Worker 在同一 session 中分析所有污点参数并生成图谱。

```
DataflowVulnWorkflow.run()

  ┌─ 初始化 ─────────────────────────────────────────────┐
  │ • 创建 vuln-scan.sqlite (SQLite WAL mode)             │
  │ • 种子污点节点 (_seed_nodes → taint_nodes 表)         │
  │ • 启动 analysis_run (analysis_runs 表)                │
  │ • 软链接源码树到 workspace                             │
  └──────────────────────────────────────────────────────┘
                           │
  ┌─ Phase 1: 单 Worker 全域分析 ─────────────────────────┐
  │ • extract_func 预提取函数体（含 L{n} 行号）             │
  │ • 注入 taint-graph prompt + followups prompt           │
  │ • Worker 产出:                                        │
  │   - taint-graph.json  (edges/followups/termination)   │
  │   - dataflow-{func}.md                                │
  │   - tainted.list / taintvars.json                     │
  │ • 脚本校验: validate_taint_graph()                     │
  │   - edges 缺失 / 无效操作类型 / 终止边缺原因 → warning │
  │   - 校验通过 → passed=True                            │
  └──────────────────────────────────────────────────────┘
                           │
  ┌─ Phase 2: Fork 漏洞挖掘 Session ──────────────────────┐
  │ • copy worker session → vuln-mining session           │
  │ • 注入 vuln-miners prompt + dataflow 文本 (≤30KB)     │
  │ • Worker 产出: findings JSON                          │
  │ • 每个 finding → VulnFindingRecord → SQLite           │
  │ • 每个 finding → output/vulnerabilities/{id}/ 目录    │
  │   ├── vulnerability-report.md (标题/摘要/证据/可利用性)│
  │   ├── taint-path-report.md (污点路径全文)              │
  │   └── context.jsonl (fork session 对话历史)            │
  └──────────────────────────────────────────────────────┘
                           │
  ┌─ Phase 3: 图谱持久化 + Followup 注册 ─────────────────┐
  │ • taint-graph.json edges → taint_edges (SQLite)       │
  │ • 解析 callees → tainted.list fallback                │
  │ • callees → followups (SQLite, status=pending)        │
  │ • 导出 vuln-scan-graph.json (全量图谱快照)             │
  │ • finish_run → analysis_runs.status=completed         │
  └──────────────────────────────────────────────────────┘
```

**设计决策 — 为什么是单 Worker 而非多 Worker？**
漏洞挖掘场景中，Worker 的核心产出是结构化的 taint-graph.json，而非自然语言报告的"质量"。多个 Worker 会产出不同的图谱版本（边的粒度、命名不一致），合并复杂度远高于单 Worker 分析。Judge 的职责也从"评价报告质量"转变为"校验图谱结构完整性"——后者通过确定性脚本（vuln_graph_validator）完成，无需 LLM。

### 5.2 Fork 策略：按需继承上下文

```
父函数 A (depth=0)
  │
  ├── worker session: A-worker.jsonl ✓ (含 A 的完整分析记忆)
  │   └── fork → A-vuln-mining.jsonl (漏洞判断)
  │
  ├── callee B (depth=1) ← 继承 A-worker.jsonl
  │   ├── worker session: B-worker.jsonl (copy from A)
  │   └── fork → B-vuln-mining.jsonl
  │
  └── callee C (depth=1) ← 继承 A-worker.jsonl (独立 fork)
      ├── worker session: C-worker.jsonl (copy from A)
      └── fork → C-vuln-mining.jsonl
```

| Fork 类型 | 目的 | 触发时机 | Session 来源 |
|:---|:---|:---|:---|
| **vuln_mining** | 当前函数漏洞判断 | Phase 1 完成后 | 复制当前 worker session |
| **followup_analysis** | 第 2..N 个 callee | callee 入队时 | 继承调用者的 worker session |

**多 callee fork 的语义**：当函数 A 有 B、C、D 三个 callee 时，B 复用主递归队列上下文，C 和 D 被标记为 `purpose=followup_analysis` 的独立 fork。每个 fork 各自从 A 的 worker session 开始，继承父函数分析记忆但不共享彼此的分析上下文。实际进程并发由 Worker Pool 的 Pod 槽位和 `callee_concurrency` 控制。

### 5.3 终止规则

污点传播在以下场景可终止，但**必须**写入图谱（`termination_reason`）：

| 终止条件 | termination_reason |
|:---|:---|
| 完整清洗/强校验后，后续只使用安全值 | `sanitized` — 清洗函数 + 效果 (partial/complete) |
| 仅流入日志/统计/调试，不影响敏感操作 | `safe_sink` — 仅日志输出 |
| 函数返回常量/错误码，污点未写入外部 | `no_external_taint_output` |
| 达到最大深度 | `depth_limit` |
| 环路检测（状态键重复） | `cycle` — 记录回边 |
| 无可解析函数定义（stdlib/宏） | `skipped/unknown` — 不直接判定安全 |

## 6. 污点图谱数据库

### 6.1 SQLite Schema

每个任务维护一个 `run/vuln-scan.sqlite`，6 张表构成完整的污点传播与漏洞图谱：

```
vuln-scan.sqlite
│
├── analysis_runs       ← 分析运行元数据
│   └── run_id, task_id, root_file, root_function, source_root, status, config_json
│
├── taint_nodes         ← 污点源和中间载体
│   └── node_id, source_file, function_name, taint_kind, symbol, line,
│       call_expr, description, parent_node_id, depth, context_session
│
├── taint_edges         ← 单函数内每条传播边 (核心)
│   └── edge_id, from_node_id, to_node_id, source_file, function_name,
│       from_symbol, to_symbol, line, operation, evidence,
│       sanitizer, sanitizer_effect, validation, termination_reason, confidence
│
├── followups           ← 需要跟入的子函数
│   └── followup_id, edge_id, parent_node_id,
│       callee_file, callee_function, callee_line,
│       tainted_params_json, status, reason, fork_session, depth
│
├── vulnerability_findings ← 漏洞发现
│   └── finding_id, run_id, node_id, edge_id,
│       vuln_type, severity, title, summary, evidence,
│       exploitability, confidence, output_dir
│
└── context_forks       ← Fork 会话记录
    └── fork_id, parent_fork_id, run_id, node_id,
        purpose, session_file, status
```

### 6.2 边的操作类型

| operation | 语义 | 示例 |
|:---|:---|:---|
| `assignment` | 直接赋值传播 | `len = buf->length` |
| `call_arg` | 作为参数传入子函数 | `Process(buf, len)` |
| `return` | 作为返回值传出 | `return tainted_ptr` |
| `field` | 字段/成员访问 | `msg->payload = buf` |
| `container` | 容器操作（数组/链表） | `list_add(&queue, item)` |
| `condition` | 条件分支依赖污点 | `if (len > MAX)` |
| `sink` | 危险操作直接使用污点 | `memcpy(dst, src, tainted_len)` |
| `terminate` | 污点传播在此终止 | 清洗/日志/返回常量 |
| `validation` | 污点被校验 | 边界检查 `if (len <= bufsize)` |
| `sanitizer` | 污点被清洗/转义 | `html_escape(input)` |

### 6.3 图谱查询 API

```
GET /api/app/dataflow-vuln-scan/tasks/{task_id}/vuln-graph
  → 返回完整图谱 JSON (analysis_runs + nodes + edges + followups + findings)

GET /api/app/dataflow-vuln-scan/tasks/{task_id}/vuln-findings
  → 返回漏洞发现列表 (vuln_type + severity + title + summary + evidence)
```

## 7. 编排引擎：Orchestrator

### 7.1 统一 VulnWorkflow 模式

Orchestrator 代码中保留了两种执行方法：

| 方法 | 工作流 | 说明 |
|:---|:---|:---|
| `execute()` | 经典多 Worker × 多 Judge 矩阵评审 | 继承自 dataflow-analyse 共享代码，保留作为兼容/非递归路径 |
| `execute_recursive()` → DataflowVulnWorkflow | 单 Worker + 脚本校验 + fork 漏洞挖掘 | **实际使用的唯一路径** |

在 `execute_recursive()` 的 BFS 队列中，**所有函数（包括根函数和递归子函数）统一使用 `DataflowVulnWorkflow`**。`process_item()` 协程对每个队列项创建 `DataflowVulnWorkflow` 实例并调用 `workflow.run()`，无分支判断。

经典 `execute()` (W+J) 仅在直接调用 `orchestrator.execute()` 时使用（非递归路径，用于单独分析单个函数而不追踪调用链），在标准的递归分析流程中不会被触发。

### 7.2 BFS 队列 + Worker Pool

```
BFS Worker Pool (n = callee_concurrency, 默认 4)
  ├── Worker 1: 根函数 A (depth=0) → DataflowVulnWorkflow
  │     → 解析 tainted.list / followups → 入队
  ├── Worker 2: callee_B (depth=1) → DataflowVulnWorkflow
  ├── Worker 3: callee_C (depth=1) → DataflowVulnWorkflow
  └── Worker 4: callee_D (depth=1) → DataflowVulnWorkflow
```

所有函数（包括根函数和所有递归子函数）统一使用 `DataflowVulnWorkflow`，由 BFS 队列分发到 Worker Pool 中的空闲协程执行。

callee 入队前的预检链（与 dataflow-analyse 相同）：
```
followups 表 / tainted.list 解析
  → 去自引用
  → 去已分析 (analyzed set)
  → 去标准库 (_STDLIB_SKIP: 40+ 函数)
  → cpp_resolver 验证函数定义
  → 构建 sub_cfg
  → queue.put((func, file, line, cfg, tid, depth+1, taint_ctx, parent_session))
```

### 7.3 Session 继承链

与 dataflow-analyse 的独立 session 不同，vuln-scan 的递归子函数采用 **session 继承** 策略：

```
run/sessions/  (全局归档目录)
├── d00-HandleCommissioningSet-worker.jsonl        ← 根函数 session
├── d00-HandleCommissioningSet-vuln-mining.jsonl    ← 根函数漏洞 fork
├── d01-SetCommissioningData-worker.jsonl           ← copy from d00-...worker.jsonl
├── d01-SetCommissioningData-vuln-mining.jsonl
├── d01-SendCommissioningSetResponse-worker.jsonl   ← copy from d00-...worker.jsonl
└── d01-SendCommissioningSetResponse-vuln-mining.jsonl
```

每个子函数 worker session 从父函数 worker session 复制而来（`shutil.copyfile`），确保子函数分析时：
- 知道调用链的上下文（父函数做了什么）
- 知道当前污点参数的来源（它来自父函数的哪个变量、哪条传播路径）
- 不会受到兄弟 callee 分析上下文的污染

## 8. 漏洞挖掘策略

### 8.1 Vuln-miners Prompt

vuln-miners 是一个独立的 fork session，其 prompt 聚焦于 **当前函数内的漏洞判断**：

```
判断原则:
  - 内存越界/长度可控拷贝 (tainted_len → memcpy)
  - 命令注入/路径穿越/格式化字符串 (tainted_str → system/sprintf)
  - 权限绕过/状态机绕过
  - use-after-free/double-free
  - 整数溢出导致长度/偏移/分配大小异常
  - 协议字段污染导致安全边界破坏

关键规则:
  - 不要把"有污点传播"直接等同于漏洞
  - 必须说明缺失的校验/清洗与危险 sink 的联系
  - 不要跨函数递归（后续 callee 会有各自的 vuln-mining fork）
```

### 8.2 漏洞分级

| Severity | 说明 |
|:---|:---|
| `critical` | 可远程利用，导致代码执行或权限提升 |
| `high` | 可导致内存破坏、信息泄露或拒绝服务 |
| `medium` | 需要特定条件组合才能利用 |
| `low` | 理论上的安全隐患，实际利用困难 |
| `info` | 安全编码建议，非漏洞 |
| `unknown` | 信息不足以判断 |

### 8.3 Finding 输出结构

```
output/vulnerabilities/{finding_id}/
├── vulnerability-report.md   ← 漏洞报告 (标题/类型/严重度/摘要/证据/可利用性)
├── taint-path-report.md      ← 导致该漏洞的完整污点传播路径
└── context.jsonl             ← vuln-mining fork session 的完整对话历史
```

## 9. 数据模型

### 9.1 配置继承

dataflow-vuln-scan 共享 dataflow-analyse 的全部配置模型（ServiceConfig → TaskConfig），新增：

| 配置 | 说明 |
|:---|:---|
| `taint_details` 扩展 | 支持 `return_value | call_argument | local | field | global` 等多种污点来源 |
| `vuln_output_root` | 漏洞输出根目录（默认 `output/vulnerabilities/`） |

### 9.2 任务结果扩展

```
TaskResult 新增字段:
├── vuln_summary: {runs, nodes, edges, followups, findings}  ← 图谱统计
└── upstream_entry_metadata:
    ├── worker_session_file: str          ← Worker session 路径 (供 callee 继承)
    └── vuln_scan:
        ├── sqlite_path: str              ← vuln-scan.sqlite 路径
        ├── graph_json_path: str          ← vuln-scan-graph.json 路径
        └── vulnerabilities_dir: str      ← 漏洞输出目录
```

## 10. 服务架构与部署

### 10.1 运行时角色

| 角色 | Deployment | Replicas | 职责 |
|:---|:---|:---|:---|
| **api** | `secflow-app-dataflow-vuln-scan` | 2 | REST API + 任务 CRUD + SSE 事件流 + 图谱/漏洞查询 + 服务注册 |
| **worker** | `secflow-app-dataflow-vuln-scan-worker` | 1 | 任务争抢 + 编排执行 + 心跳续租 + 卡死检测 |

**api Pod** (2 CPU / 4 GiB):
- `DVS_ENABLE_PUBLIC_API=true`，`DVS_ENABLE_DISPATCHER=false`，`DVS_ENABLE_EXECUTOR=false`

**worker Pod** (6 CPU / 12 GiB request, 8 CPU / 16 GiB limit):
- `DVS_ENABLE_EXECUTOR=true`，`DVS_ENABLE_DISPATCHER=true`
- `DVS_MAX_LOCAL_RUNNING_TASKS=4` — 单 Pod 最多并发 4 个分析任务
- `DVS_LEASE_TTL_SECONDS=300` — 任务租约 5 分钟
- `DVS_HEARTBEAT_INTERVAL_SECONDS=60` — 心跳 1 分钟

### 10.2 槽位管理 (execution_coordinator.py)

Worker Pod 通过 `execution_coordinator` 管理 Agent 进程槽位：

```
每个 Worker Pod:
  • 全局 Agent 槽位池 (受 DVS_MAX_LOCAL_RUNNING_TASKS 限制)
  • 每个分析任务内部:
    - 单 Worker session (1 个槽位)
    - vuln-mining fork session (1 个槽位，与 Worker 串行)
    - BFS callee 并发 (callee_concurrency 个槽位)
  • 总槽位 = MAX_LOCAL_RUNNING_TASKS × (1 + callee_concurrency)
```

### 10.3 外部依赖

| 服务 | 用途 |
|:---|:---|
| MySQL | 任务状态、事件持久化（表前缀 `app_dvs_`） |
| Nacos | 服务注册与 LLM Provider 配置同步 |
| NFS PVC (`/data`) | 共享文件系统（源码、输出、session 文件、SQLite） |
| Harbor | Docker 镜像仓库 |

## 11. 与 SecFlow 流水线的集成

dataflow-vuln-scan 是 binary-security 端到端流水线的第五个阶段（最终阶段）：

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
    │ 产物: functions.list
    ▼
dataflow-analyse (污点传播追踪)
    │ 产物: dataflow/ + final_report.md
    ▼
dataflow-vuln-scan (漏洞挖掘) ← 本节所述
    │ 输入: dataflow/ + source_root_path + taint_details
    │ 产物: vuln-scan.sqlite + vuln-scan-graph.json
    │       + output/vulnerabilities/ + final_report.md
    ▼
(可继续迭代: entry-analyse → dataflow-analyse → dataflow-vuln-scan)
```

**上游输入契约**（来自 dataflow-analyse）：
```
TaskConfig
├── source_file / function_name / line_hint
├── taint_params / taint_details (含 source_kind + description)
├── function_description / entry_reason (来自 entry-analyse)
├── source_root_path ← 真实源码根目录
└── module_input_path ← 模块输入目录（含 files.list 等上下文）
```

## 12. 目录结构

```
{output_dir}/{task_id}/
├── output/                          ← 最终交付件
│   ├── flag                        ← 1=成功 / 0=失败
│   ├── final_report.md             ← 合并后的跨函数数据流 + 漏洞报告
│   ├── dataflow/                   ← 逐函数分析文件
│   │   └── {FuncName}.md
│   └── vulnerabilities/            ← 漏洞发现
│       └── {finding_id}/
│           ├── vulnerability-report.md
│           ├── taint-path-report.md
│           └── context.jsonl
│
├── run/                             ← 运行时产物
│   ├── vuln-scan.sqlite            ← 污点图谱数据库（核心）
│   ├── vuln-scan-graph.json        ← 图谱 JSON 快照
│   ├── sessions/                   ← 全局 Session 归档
│   │   ├── d00-{root_func}-worker.jsonl
│   │   ├── d00-{root_func}-vuln-mining.jsonl
│   │   ├── d01-{callee}-worker.jsonl    ← copy from parent
│   │   └── d01-{callee}-vuln-mining.jsonl
│   ├── dataflow/                   ← 子函数数据流文件
│   │   └── {FuncName}.md
│   ├── report.md                   ← 分析摘要
│   ├── result.json                 ← 结构化结果
│   ├── workspace-worker-0/         ← Worker 工作目录
│   │   ├── [源文件符号链接]
│   │   ├── taint-graph.json        ← LLM 产出的图谱
│   │   ├── dataflow-{func}.md
│   │   ├── tainted.list
│   │   └── taintvars.json
│   └── subtasks/                   ← 递归子函数中间产物
│       └── depth_01/
│           └── {tid}-{FuncName}/
│               ├── vuln-scan.sqlite
│               ├── sessions/
│               └── workspace-worker-0/
│
└── events/                          ← 任务事件流
```

## 13. Prompt 体系

| Prompt | 使用者 | 用途 |
|:---|:---|:---|
| `prompts/workers/default.md` | Worker | 单函数污点分析系统提示词 |
| `prompts/judges/default.md` | Judge | 评审验证系统提示词 |
| `prompts/taint-graph/default.md` | Worker | 污点图谱抽取格式规范 (taint-graph.json schema) |
| `prompts/vuln-miners/default.md` | Vuln Mining Fork | 漏洞判断原则 + findings JSON 输出规范 |
| `prompts/followups/default.md` | Worker (depth>0) | 跟入函数分析时的上下文继承说明 |
| `prompts/merge/default.md` | Merge Agent | 合并所有 dataflow 文档为最终报告 |

### Skills

| Skill | 使用者 | 用途 |
|:---|:---|:---|
| `write-taint-graph` | Worker | taint-graph.json 写入规范 |
| `mine-dataflow-vulnerability` | Vuln Mining Fork | 漏洞模式识别与报告 |
| `write-taint-flow` | Worker | 单污点传播路径报告 |
| `write-dataflow` | Worker | 最终 dataflow 报告格式 |

## 14. 配置参考

### 关键参数

| 参数 | 默认值 | 说明 |
|:---|:---|:---|
| `max_rounds` | -1 (∞) | 每函数最大 W+J 轮数 |
| `min_rounds` | 1 | 最少轮数 |
| `max_trace_depth` | 3 | 调用链递归最大深度 |
| `callee_concurrency` | 4 | BFS 工作池并发数 |
| `worker_count` | 1 | 单函数内并行 Worker 数 |
| `judge_count` | 1 | 单函数内并行 Judge 数 |
| `agent_max_retries` | 100 | API 级错误重试上限 |
| `agent_run_timeout_seconds` | 3600 | 单次 Agent run 超时 |

## 15. 设计原则

| # | 原则 |
|:---|:---|
| 1 | **图谱即 ground truth** — SQLite 是污点传播的唯一权威记录。LLM 产出 taint-graph.json，脚本校验后写入 SQLite；后续所有漏洞判断都基于 SQLite 中的边，而非 LLM 的自由文本 |
| 2 | **单 Worker 全域分析，脚本替代 LLM 校验** — 漏洞挖掘中 Worker 产出图谱（结构化 JSON），vuln_graph_validator 做确定性结构校验（edges 完整性/操作类型合法性/终止边原因），Judge 的职责被脚本承接 |
| 3 | **Fork 隔离，按需继承** — vuln-mining fork 从 worker session 复制上下文但独立分析（不污染主分析）；callee fork 只继承直接调用者的 session（不继承整个调用链历史） |
| 4 | **边分析边挖掘** — 每层函数分析完成后立即启动 vuln-mining fork 判断漏洞，而非等全链分析完后再回溯。漏洞发现的时效性得到保证 |
| 5 | **Session 继承，非全程共享** — 子函数从父函数 worker session 复制（`shutil.copyfile`）后独立运行，既获得调用链上下文又不污染兄弟 callee |
| 6 | **图谱可审计** — SQLite WAL 模式支持并发读写，所有边/节点/finding 带时间戳；vuln-scan-graph.json 作为全量快照供前端可视化 |
| 7 | **BFS 广度优先，工作池并发** — 兄弟 callee 并发分析（asyncio.gather），callee_concurrency 控制工作池大小 |
| 8 | **预检过滤，避免无效 W+J** — cpp_resolver + _STDLIB_SKIP + analyzed set 去重，在启动昂贵的 LLM 流水线前完成确定性过滤 |
| 9 | **多 callee fork 语义** — 第一个 callee 复用主递归上下文，第 2..N 个标记为独立 fork，由 Worker Pool 按 Pod 槽位调度，避免上下文爆炸 |
| 10 | **漏洞独立归档** — 每个 finding 有独立目录（vulnerability-report.md + taint-path-report.md + context.jsonl），支持独立的展示、审计和复现 |

## 16. 与 dataflow-analyse 的差异

| 维度 | dataflow-analyse | dataflow-vuln-scan |
|:---|:---|:---|
| **定位** | 污点传播路径追踪 | 漏洞模式识别与验证 |
| **Worker 策略** | PerTaintWorkflow：参数级并行 + summary 合并 | 单 Worker 全域分析：所有污点同一 session |
| **核心产物** | dataflow-{func}.md + tainted.list | taint-graph.json + vuln-scan.sqlite + findings |
| **Judge/校验** | LLM Judge 评审报告质量（评分 + 反馈路由） | 脚本校验图谱结构（vuln_graph_validator） |
| **Fork 机制** | 无 | vuln-mining fork（漏洞判断）+ followup fork（多 callee） |
| **Session 策略** | 独立 session（taint/summary 各自隔离） | Session 继承（子函数从父函数复制） |
| **图谱** | 无 | SQLite 6 张表持久化完整污点传播图 |
| **漏洞发现** | 无（仅追踪传播） | 每个函数分析后立即启动漏洞判断 fork |
| **API 新增** | — | GET /vuln-graph + GET /vuln-findings |

## 17. 与 Legacy Scanner 的关系

`dataflow-vuln-scanner`（legacy）是本系统的前身，是一个 JSON 配置驱动的通用 AI 工作流引擎：

| 维度 | dataflow-vuln-scanner (legacy) | dataflow-vuln-scan (当前) |
|:---|:---|:---|
| **配置方式** | JSON 配置定义 Pipeline（Stages → Tasks → Agents） | 代码内建 Pipeline（固定三阶段） |
| **扩展性** | Python 插件化（通过 services/ 目录扩展） | 专用架构（通过 Prompt/Skill 定制行为） |
| **并发模型** | 全局 Worker Pool + result_review 队列 | BFS Worker Pool + fork session |
| **图谱** | 无 | SQLite 6 表持久化 |
| **适用场景** | 通用 AI 工作流（不仅限于漏洞扫描） | 专注数据流漏洞挖掘 |

Legacy scanner 仍保留在代码库中以供参考和向后兼容，但新任务统一使用 dataflow-vuln-scan。

## 18. 性能参考

| 场景 | 函数数 | 深度 | 每函数耗时（含 vuln-mining fork） | 总耗时 |
|:---|:---|:---|:---|:---|
| 单入口浅调用链 | 1-3 | 1 | 3-10 min | 3-30 min |
| 中等复杂度模块 | 5-12 | 2-3 | 4-12 min | 30-90 min |
| 大型复杂模块 | 15-40 | 3-4 | 5-15 min | 1.5-5 h |

> 每函数耗时 = Worker 分析（3-8 min）+ vuln-mining fork（1-4 min）。session 继承避免了重复的"阅读源码"阶段。漏洞发现数量取决于代码中实际的安全模式密度，典型固件模块（如 OpenThread 协议栈）中每 3-8 个函数可发现 1 个值得关注的漏洞候选。

---
> 文档版本：`v2.1` @ `5e4b6467` · 子模块 `329c94d`（2026-06-05）
