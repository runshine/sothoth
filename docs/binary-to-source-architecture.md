# binary-to-source 架构设计

## 1. 定位

binary-to-source 是 SecFlow 分析流水线中的**二进制逆向子系统**，由两层组成：

- **binary-to-source（适配层）**：位于 SecFlow 前端与 pi-re-agent 之间的编排适配服务。负责任务队列管理、ELF 派发调度、结果缓存、状态同步、路径隔离和安全校验。不做任何逆向计算。
- **pi-re-agent（引擎层）**：独立的二进制逆向执行引擎。通过 IDA Pro 反编译 + LLM 批量生成函数体 + 静态验证 + 合并，将 ELF 共享库还原为可读的 C 源码。

两层通过 REST API 解耦：适配层调用 `POST /api/v1/jobs` 派发任务，通过 `GET /jobs/{id}` 轮询进度，pi-re-agent 在自己的 Worker Pool 中并发执行。

## 2. 挑战

二进制逆向面临四个核心矛盾：

**精度与规模。** 一个典型的嵌入式 ELF 共享库包含 200-800 个函数。让 LLM Agent 逐个分析每个函数精细度最高，但每次 tool call（读反编译输出、查交叉引用）的开销在 10-30 秒级别——800 个函数意味着数小时的 LLM 调用。需要找到一种方式在"Agent 的智能"和"直接补全的速度"之间取得平衡。

**语义与结构的分离。** 逆向中最难的不是翻译汇编，而是恢复语义——函数名、类型签名、结构体布局、调用约定。这些语义信息只有在理解"这个模块在做什么"之后才能推断。但函数体本身可以通过直接 LLM 补全高效生成——只需要给它一个冻结的共享头文件。

**重复计算与存储膨胀。** 同一个 ELF 在不同项目中重复出现，每次重新逆向浪费 GPU 算力。缓存是必要的，但不能简单地复制整棵输出树——需要剔除 IDA 中间产物（_ida.c、.re_work_*），只保留最终交付件。

**集群调度的不对称性。** pi-re-agent Worker 的计算能力远小于适配层的派发能力——单个 Worker 可能只能并行 2-4 个 Job，但适配队列中可能有数十个待执行 Item。派发决策必须基于实时的集群容量，不能盲目光靠重试。

## 3. 核心能力

系统回答三个问题：

| | 问题 | 方式 |
|:---|:---|:---|
| ① | 这个 ELF 里有什么函数？ | IDA Pro 反编译：提取所有函数的反编译输出、签名、交叉引用；按机器码字节数分 batch |
| ② | 如何高效还原函数体？ | hybrid 引擎：Agent 合成冻结头文件（语义理解）+ 直接 LLM 批量补全函数体（速度） + 静态验证（确定性检查） |
| ③ | 如何避免重复计算？ | 内容哈希 → 共享缓存。命中时剔除 IDA 中间产物后物化 |

## 4. 总体架构

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     SecFlow 前端 (React + Vite)                          │
│                     /api/app/binary-to-source                            │
└────────────────────────────┬─────────────────────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────────────────────┐
│              binary-to-source 适配层 (FastAPI, Python)                    │
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │ Task Service │  │  Dispatcher  │  │ Task Syncer  │  │    Cache    │ │
│  │              │  │              │  │              │  │   Service   │ │
│  │ • Task CRUD  │  │ • 集群容量   │  │ • 状态轮询   │  │ • SHA256 哈希│ │
│  │ • Item 管理  │  │ • 排他租约   │  │ • 事件持久化 │  │ • 产物物化   │ │
│  │ • 状态映射   │  │ • 派发决策   │  │ • 阶段记录   │  │ • IDA 产物   │ │
│  │ • 路径隔离   │  │ • 负载分发   │  │ • 函数统计   │  │   过滤       │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ │
│         │                 │                 │                 │        │
│         │   ┌─────────────┴─────────────────┴─────────────────┘        │
│         │   │                                                          │
│         │   ▼                                                          │
│         │  ┌──────────────────────────────────────────────────┐        │
│         │  │         PiReAgentClient (httpx AsyncClient)       │        │
│         │  │                                                  │        │
│         │  │  POST /api/v1/jobs              创建逆向任务     │        │
│         │  │  GET  /api/v1/jobs/{id}         查询进度         │        │
│         │  │  GET  /api/v1/jobs               列出所有任务     │        │
│         │  │  POST /api/v1/jobs/{id}/cancel  取消任务         │        │
│         │  │  GET  /api/v1/health             Worker 健康     │        │
│         │  └──────────────────────────────────────────────────┘        │
└─────────┼───────────────────────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────────────────┐
│               pi-re-agent 引擎层 (FastAPI, Python)                       │
│                                                                          │
│  ┌─────────────────────┐  ┌──────────────────────────────────────────┐  │
│  │   REST API          │  │          Worker Pool                     │  │
│  │   api/app.py        │  │          api/worker.py                   │  │
│  │                     │  │                                          │  │
│  │  • Job CRUD         │  │  • DB 租约争抢 (claim)                   │  │
│  │  • 路径安全校验     │  │  • 并发控制 (MAX_CONCURRENT_JOBS)        │  │
│  │  • JobStore (SQL)   │  │  • 心跳续约 (HEARTBEAT_SECONDS)          │  │
│  └─────────────────────┘  │  • 进度回写 (progress + active_batches)  │  │
│                           │  • 卡死检测 (STUCK_SCAN_SECONDS)         │  │
│                           └────────────────┬─────────────────────────┘  │
│                                            │                            │
│  ┌─────────────────────────────────────────▼──────────────────────────┐ │
│  │                    逆向执行引擎                                      │ │
│  │                                                                     │ │
│  │  ┌────────────────────────────────────────────────────────────┐    │ │
│  │  │              PipelineRunner (core/pipeline.py)              │    │ │
│  │  │  公共确定性阶段：目录初始化 → IDA 分析 → 函数过滤 → 分批    │    │ │
│  │  └────────────────────────────────────────────────────────────┘    │ │
│  │                            │                                        │ │
│  │         ┌──────────────────┼──────────────────┐                    │ │
│  │         ▼                  ▼                  ▼                     │ │
│  │  ┌────────────┐   ┌──────────────┐   ┌──────────────┐             │ │
│  │  │   agent    │   │   hybrid ★   │   │    turbo     │             │ │
│  │  │   engine   │   │   engine     │   │   engine     │             │ │
│  │  │ (legacy)   │   │  (默认)       │   │  (变体)      │             │ │
│  │  └────────────┘   └──────────────┘   └──────────────┘             │ │
│  │                                                                     │ │
│  │  hybrid 引擎五阶段流水线:                                            │ │
│  │                                                                     │ │
│  │  Phase 1: IDA 分析               idat -A 反编译全部函数              │ │
│  │      │                                                              │ │
│  │  Phase 2: 分批                  按机器码字节数创建 batches           │ │
│  │      │                                                              │ │
│  │  Phase 3: 头文件合成             Agent 生成冻结共享头文件            │ │
│  │      │                           + 确定性审计 + 冒烟编译修复         │ │
│  │      │                                                              │ │
│  │  Phase 4: 函数体生成             直接 LLM 批量并行生成函数体         │ │
│  │      │                           + 静态验证 (per-batch)             │ │
│  │      │                           + 重试 (max_retries=2)             │ │
│  │      │                                                              │ │
│  │  Phase 5: 合并                   target.c + target.h + target.asm   │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
```

## 5. pi-re-agent 引擎层：hybrid 引擎详解

hybrid 引擎是默认引擎，其核心设计理念是**"Agent 只做语义推断，速度留给直接补全"**——将 LLM 算力集中用于唯一需要上下文理解的步骤（头文件合成），其它步骤用最直接的方式完成。

### 5.1 五阶段流水线

```
ELF 共享库 (.so)
        │
   ┌────▼──────────────────────┐
   │  Phase 1: IDA 分析         │
   │  ────────────────────────  │
   │  • idat -A 自动反编译      │
   │  • 提取所有函数签名/大小    │
   │  • 输出: functions.json    │
   │    + decompiled.c (全量)   │
   │    + metadata.json (架构)  │
   └────┬──────────────────────┘
        │
   ┌────▼──────────────────────┐
   │  Phase 2: 分批            │
   │  ────────────────────────  │
   │  • 按机器码字节数聚合      │
   │    (默认 batch_size=8KB)  │
   │  • 每批生成 batch_NNN.c    │
   │    (仅含对应函数的反编译)   │
   │  • 可选: 函数过滤          │
   └────┬──────────────────────┘
        │
   ┌────▼──────────────────────┐
   │  Phase 3: 头文件合成       │
   │  ────────────────────────  │
   │  • pi Agent 生成全局共享   │
   │    头文件 (preamble.h):    │
   │    - 类型定义 (typedefs)   │
   │    - 结构体布局            │
   │    - 函数原型声明          │
   │    - 全局变量 extern       │
   │                            │
   │  • 确定性审计:              │
   │    - 无占位符 (TODO/...)   │
   │    - 无冲突 extern         │
   │    - 无重复 typedef        │
   │    - 无未声明标识符        │
   │                            │
   │  • 冒烟编译修复:            │
   │    gcc -fsyntax-only       │
   │    → 最多 max_repair_      │
   │      attempts=2 次修复     │
   │                            │
   │  ★ 冻结后不再改变           │
   └────┬──────────────────────┘
        │
   ┌────▼──────────────────────┐
   │  Phase 4: 函数体生成       │
   │  ────────────────────────  │
   │  • 直接 LLM 补全 (非Agent) │
   │  • 每 batch 独立调用:      │
   │    System: preamble.h +    │
   │      函数反编译 + 反汇编    │
   │    User: "把这些函数还原    │
   │      为 C 代码"            │
   │                            │
   │  • concurrency=4 并行      │
   │                            │
   │  • 静态验证 (per-batch):   │
   │    - 完整性: 所有函数都有   │
   │      定义 ≠ 空/占位符      │
   │    - 调用忠实度: 反汇编中   │
   │      的 call 在 C 中出现   │
   │    - 截断检测: 括号不匹配   │
   │      → 要求完整输出        │
   │                            │
   │  • 不通过 → 重试 (最多2次) │
   └────┬──────────────────────┘
        │
   ┌────▼──────────────────────┐
   │  Phase 5: 合并 + 后处理   │
   │  ────────────────────────  │
   │  • 合并所有 batch_NNN.c    │
   │    → target.c             │
   │  • 复制 preamble.h         │
   │    → target.h             │
   │  • 复制 IDA 原始反编译     │
   │    → target_ida.c         │
   │                            │
   │  • 后处理 (postprocess):   │
   │    - 类型标准化 (__int64   │
   │      → int64_t 等)        │
   │    - 空壳函数补全          │
   │    - IDA Helper 宏展开     │
   │    - 公共运行时声明注入    │
   └────────────────────────────┘
```

### 5.2 核心设计决策

**为什么 Agent 只用于头文件？** 头文件合成需要理解全局语义——哪些类型是同一个结构体、哪些函数属于同一接口、调用约定是什么。这些判断需要 agent 的 tool call 能力（读 IDA 反编译输出、查交叉引用）。相比之下，函数体生成是高度局部化的——给一个函数签名 + 反编译 + 反汇编 + 冻结的类型上下文，LLM 可以完全通过单次补全完成。

**为什么用静态验证替代 LLM Validator？** 旧版 `agent` 引擎使用 LLM Validator Agent 评审每个 batch（耗时 ~30s/batch）。新版用确定性的正则/grep 检查取代——微秒级完成，覆盖完整性、调用忠实度和截断三大类问题。LLM 评审只在"验证结论需要语义理解的边缘情况"时才保留价值。

**为什么需要冒烟编译？** LLM 生成的头文件可能包含语法错误（缺少分号、括号不匹配）或语义冲突（重复定义、未声明类型）。`gcc -fsyntax-only` 在毫秒级发现这些问题，然后 agent 修复——这比依赖 LLM 自我纠错高效得多。

### 5.3 引擎对比

| 特性 | agent (legacy) | hybrid ★ (默认) | turbo (变体) |
|:---|:---|:---|:---|
| 头文件生成 | Executor Agent | Agent (同上) | = hybrid |
| 函数体生成 | Executor Agent (tool-call) | 直接 LLM 批量补全 | = hybrid + 更快 |
| 验证 | LLM Validator Agent | 静态规则 (grep/regex) | = hybrid |
| 并发 | 无 (串行) | concurrency=4 | = hybrid |
| 适用场景 | 高精度需求 | 通用 | 快速原型 |

### 5.4 IDA 集成

```
pi-re-agent                         IDA Pro
────────                            ───────
run_ida(target, cache_dir)
    │
    ├── idat -A -S"ida_export.py" target.so
    │    │
    │    └── 自动分析 → Hex-Rays 反编译 → 导出:
    │         ├── functions.json   [函数名/地址/大小/类型]
    │         ├── decompiled.c     [全量反编译输出]
    │         └── metadata.json    [arch/bits/endian]
    │
    └── 缓存: 已分析的 .i64 数据库存入 ida_cache/
         下次 clean=false 时直接复用
```

### 5.5 REST API

```
POST /api/v1/jobs                   创建逆向任务
  Body: { target, output_dir,
          batch_size, max_retries,
          model, engine, concurrency,
          idempotency_key }

GET  /api/v1/jobs                   列出所有任务
GET  /api/v1/jobs/{id}              查询任务 (含 Progress + OutputPaths)
POST /api/v1/jobs/{id}/cancel       取消任务
GET  /api/v1/jobs/{id}/status       简化状态查询
GET  /api/v1/health                 健康检查
GET  /api/v1/capacity               容量信息 (max/running/queued slots)
```

### 5.6 JobStore：SQL 任务存储

```
pi_re_jobs 表
├── id (UUID) + status (queued/running/completed/failed/cancelled)
├── target + active_target_key (SHA256, UNIQUE 防重复)
├── phase (analyzing/batching/header_synthesis/processing/merging)
├── progress_json (Progress: 当前 batch/attempt/function 等)
├── output_json (OutputPaths: .c/.h/_ida.c 路径)
├── idempotency_key (UNIQUE, 幂等创建)
├── worker_id + worker_lease_until + heartbeat_at (Worker 租约)
└── created_at + updated_at + started_at + finished_at
```

### 5.7 Worker Pool：并发执行

```
Worker Pool (api/worker.py)
│
├── claim_loop (每 HEARTBEAT_SECONDS=15s)
│   ├── 扫描 status=queued 且无有效 worker_lease 的 Job
│   └── claim: SET worker_id + lease_until = now+120s
│
├── dispatch_loop
│   ├── 统计当前 worker 的 running_jobs < MAX_CONCURRENT_JOBS (默认 2)
│   ├── 取最早 claimed job → 提交到 ThreadPoolExecutor
│   └── 执行中: 心跳续约 (每 15s 更新 heartbeat_at)
│
├── stuck_scan_loop (每 STUCK_SCAN_SECONDS=30s)
│   └── 扫描 heartbeat_at 超过 300s 未更新的 running job
│       → 回收 (status 改为 failed, worker_id 清空)
│
└── progress 同步
    └── 引擎回调 on_progress → Progress 对象 → 写回 DB
        (total_batches / current_batch / current_function / active_batches)
```

## 6. 适配层：binary-to-source 详解

### 6.1 数据模型

```
B2STask (1:N B2STaskItem)
├── id, project_id, name, status
├── task_origin_type + parent_* 字段 (binary-security 编排集成)
│
└── B2STaskItem
    ├── elf_path + output_dir         ← 输入/输出路径
    ├── pi_job_id                     ← 映射到 pi-re-agent Job
    ├── status + phase + progress     ← 从 pi-re-agent 同步
    ├── dispatch_status + dispatch_attempts + scheduler_owner
    │                                  ← 调度状态
    ├── generated_files               ← 还原的源码文件列表
    └── started_at + finished_at
```

### 6.2 状态映射

```
pi-re-agent Job Status     →    B2S Item Status
───────────────────────         ────────────────
queued                   →     queued
running                  →     running
completed                →     success
failed / max_rounds_     →     failed
  exceeded / max_retries_
  reached / timeout_...
cancelled                →     cancelled

pi-re-agent Phase        →     B2S Phase
────────────────────         ──────────
analyzing                →    ida
batching                 →    batching
header_synthesis         →    header
processing               →    body
merging                  →    merge
—                        →    completed
```

### 6.3 后台组件

| 组件 | 文件 | 职责 |
|:---|:---|:---|
| **Dispatcher** | `dispatcher.py` | 3s 间隔循环：刷新集群容量 → 获取排他租约 → 按可用槽位从队列取 pending Item → POST /api/v1/jobs 派发 |
| **Task Syncer** | `task_syncer.py` | 2s 间隔循环：扫描活跃 Task → 遍历其 Items → GET /api/v1/jobs/{pi_job_id} → 状态映射回写 + 事件持久化 + 阶段/Batch 记录更新 + 函数统计刷新 |
| **PiClusterMonitor** | `pi_cluster.py` | 30s 间隔刷新：K8s DNS 发现 Worker URL → 探测 /health + /api/v1/jobs 统计 → 计算 available_slots |
| **Cache Service** | `cache_service.py` | 创建 Task 时查 SHA256(ELF) + mode → 命中则物化产物、剔除 IDA 中间文件；success 后自动写入缓存 |

### 6.4 事件系统

每个 Task 维护一条 append-only 事件流水（`B2STaskEvent`），记录所有关键状态变更：

| 事件类型 | 触发时机 |
|:---|:---|
| `pi_job_bound` / `worker_assigned` | Item 绑定 pi-re-agent Job / Worker |
| `item_status_changed` / `phase_changed` | Item 状态/阶段变更 |
| `body_batch_started` / `body_batch_finished` | 函数体恢复 Batch 的起止 |
| `batch_attempt_started` / `function_progress` | Batch Attempt / 当前函数变更 |
| `batch_progress_updated` / `progress_snapshot_synced` | 批次进度更新 |
| `job_completed` / `job_failed` / `job_cancelled` | Job 终态 |
| `abnormal_reason_recorded` | 异常原因（分类 + 错误码 + 证据链 + 修复建议） |

通过 `dedupe_key`（SHA256 哈希）防止重复写入。

### 6.5 适配层设计原则

| # | 原则 |
|:---|:---|
| 1 | **适配不是中转** — 不做任何逆向计算，只做状态映射和编排 |
| 2 | **缓存即物化** — 命中缓存时直接复制产物，Item 不区分来源 |
| 3 | **状态由 Syncer 驱动** — Item 状态更新统一从 pi-re-agent 拉取 |
| 4 | **事件不可变** — append-only 事件 + Dedupe Key，完整可审计时间线 |
| 5 | **路径强制隔离** — 所有路径限定在 `/data/files/{project_id}` 下 |
| 6 | **分布式租约** — Dispatcher 和 Task Syncer 通过 DB 排他租约保证多副本安全 |
| 7 | **容量感知调度** — 基于实时 Worker 可用槽位派发，不盲目重试 |
| 8 | **阶段粒度可观测** — B2STaskPhase + B2STaskBatch 记录每阶段/每 Batch 指标 |
| 9 | **缓存只缓存成功** — 不缓存失败产物，避免污染缓存池 |

## 7. 引擎层设计原则

| # | 原则 |
|:---|:---|
| 1 | **Agent 只做语义推断** — 头文件合成用 Agent（需要 tool call 理解全局语义），函数体用直接补全（局部翻译不需要 tool call） |
| 2 | **静态验证替代 LLM 评审** — 完整性/调用忠实度/截断检测用确定性正则完成，微秒级 vs 30s LLM 评审 |
| 3 | **冒烟编译做最终裁判** — 生成的头文件必须通过 gcc -fsyntax-only，不通过则 Agent 修复 |
| 4 | **冻结即不可变** — Phase 3 产出的 preamble.h 在 Phase 4 中不修改，保证函数体生成的一致性引用 |
| 5 | **重试有上限** — 每个 batch 最多重试 2 次（防止无限循环），头文件修复最多 2 次 |
| 6 | **进度全量可观测** — 引擎的 on_progress 回调将 current_batch/current_attempt/current_function 实时推送到 API 层 |
| 7 | **确定性阶段与 AI 阶段分层** — PipelineRunner 封装所有确定性操作（目录/IDA/分批/Manifest），具体引擎只实现 LLM 相关逻辑 |

## 8. 两层的协作与边界

```
                    binary-to-source (适配层)
                    ═══════════════════════
                    职责:
                    • 前端 API 兼容
                    • 项目权限校验
                    • 路径安全隔离
                    • 任务队列管理
                    • 缓存管理
                    • 状态聚合与事件
                    • 函数统计
                    • Agent Session 索引

                         │ REST API
                         │
                    pi-re-agent (引擎层)
                    ═══════════════════════
                    职责:
                    • IDA Pro 反编译
                    • LLM Agent 头文件合成
                    • 直接 LLM 函数体补全
                    • 静态验证
                    • 冒烟编译修复
                    • 产物合并与后处理
                    • Worker 并发控制
                    • 卡死检测与恢复
```

**边界纪律**：
- 适配层不包含任何 LLM 调用或 IDA 调用
- 引擎层不感知项目、用户、权限
- 适配层通过轮询同步状态（不推送）
- 引擎层通过 `on_progress` 回调实时更新内部状态，适配层从 API 定期拉取

## 9. 产物契约

pi-re-agent 为每个 ELF 产出三个文件（作为 Job 的 OutputPaths 返回）：

| 文件 | 内容 | 说明 |
|:---|:---|:---|
| `{target}.c` | 合并后的完整 C 源码 | 所有 batch_NNN.c 的聚合，含文件头注释（架构/函数数） |
| `{target}.h` | 共享头文件 | preamble.h 的副本，含所有类型定义/函数原型/全局变量声明 |
| `{target}_ida.c` | IDA 原始反编译输出 | 未经 LLM 处理的 Hex-Rays 反编译结果，供审计对比 |

binary-to-source 缓存时会剔除 `_ida.c`（IDA 特定中间产物）和 `.re_work_*` 目录（引擎工作目录），只保留最终的 `.c` 和 `.h`。

## 10. 与 SecFlow 流水线的集成

```
binary-security (总编排)
    │
    ▼
firmware-unpacker (解包)
    │
    ▼
system-analyse (模块分类)
    │ 产物: modules/<mod>/files.list
    ▼
binary-to-source (二进制逆向)
    │ 输入: 每个模块的 ELF 二进制文件列表
    │ 对每个 ELF:
    │   1. 查缓存(可选) → 命中则跳过
    │   2. 派发到 pi-re-agent Worker
    │   3. 轮询直到完成
    │ 产物: 每个 ELF → .c + .h + _ida.c
    │       + module_input_path（entry-analyse 输入契约）
    │
    ▼
entry-analyse → dataflow-analyse → dataflow-vuln-scan
```

通过 `parent_project_id`、`parent_task_id`、`parent_task_type`、`parent_stage_name`、`parent_stage_item_id`、`parent_stage_item_key` 等字段与 binary-security 编排器联动。

## 11. 部署架构

```
Kubernetes
│
├── secflow-app-binary-to-source-manager  (适配层)
│   ├── api Pod:     HTTP :80, Menu 注册, 权限校验
│   └── worker Pod:  Dispatcher + Task Syncer + Cache
│
├── secflow-app-binary-to-source-pi-re-agent  (引擎层)
│   ├── Worker × N (N 取决于集群资源)
│   │   ├── 每个 Worker: MAX_CONCURRENT_JOBS=2
│   │   ├── IDA Pro (idat) 已安装
│   │   └── pi CLI + models.json (共享 LLM 配置)
│   │
│   └── Service: pi-re-agent:80
│
└── 共享存储
    ├── /data/files/{project_id}/  (项目隔离)
    └── /data/files/.secflow-cache/binary-to-source/ (全局缓存)
```

## 12. 技术栈

| 层次 | 技术 |
|:---|:---|
| **适配层框架** | Python FastAPI + uvicorn + SQLAlchemy + httpx |
| **引擎层框架** | Python FastAPI + uvicorn + SQLAlchemy + httpx |
| **AI Agent** | pi CLI (RPC mode, stdin/stdout JSON-RPC) |
| **直接 LLM 调用** | httpx → OpenAI-compatible API (同步, 重试 + 退避) |
| **逆向工具** | IDA Pro 9.x (idat CLI) + Hex-Rays Decompiler |
| **静态验证** | Python regex/grep + gcc -fsyntax-only |
| **数据库** | MySQL / SQLite (双端各独立) |
| **并发** | asyncio (适配层) + ThreadPoolExecutor (引擎层) |
