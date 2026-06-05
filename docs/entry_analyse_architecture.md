# SecFlow Entry Analyse 架构设计

## 1. 定位

Entry Analyse 是一套模块外部入口自动化分析系统。它接收 C/C++ 模块的源文件清单，通过 **Worker + Judge 六阶段流水线**扫描全部代码，识别外部数据首次进入该模块的总入口函数，产出结构化入口清单（`functions.list`）供下游 Binary Security 编排引擎消费。

## 2. 挑战

大型 C/C++ 代码库中存在一个结构性矛盾：**函数数量与入口数量的巨大落差**。一个模块可能有数百个函数（例如 IPSec 协议栈单文件即含 400+ 函数），但真正的"外部入口"——外部数据首次进入该模块的函数——往往只有数个到十数个。手工从数百个函数中甄别入口，需要逐函数阅读代码、追踪数据流、分辨"总入口"与"内部子处理函数"，单模块耗时以人天计。

LLM 改变的不是"AI 比人聪明"，而是入口甄别的单位成本结构。当单函数分析成本从 ¥5-20 降到 < ¥0.05 时，"全量逐函数分析"从不可能变成了可能。

Entry Analyse 不做抽样、不依赖启发式规则。它抓住的核心突破点：**不是用 AI 替代人工做同样的工作，而是重新定义了入口分析的形态——从"人工逐函数阅读"到"六阶段自动化流水线"**。

## 3. 核心概念

### 3.1 外部入口定义

外部入口 = **外部数据第一次进入该模块的函数**。分两类：

| 类型 | Tag | 说明 | 污点来源 |
|------|-----|------|---------|
| 被动回调型 | P | 被框架 / 分发表直接调用，数据由参数传入 | 函数参数 |
| 主动拉取型 | A | 函数内部调用 `recv`/`read`/`mmap` 等系统调用 | I/O 返回值或输出缓冲区 |

系统只找**总入口**，不找内部子处理函数——后者由下游 Binary Security 编排引擎通过 DFA（数据流分析）自行追踪。

### 3.2 两层判别

入口甄别本质上是两层判别：

| 层 | 问题 | 阶段 |
|:---|:---|:---|
| ① 函数级 | 这个函数是否有外部输入？ | R3 — 外部输入分析 |
| ② 模块级 | 即使有外部输入，它是否只是内部子步骤？（即其调用者也是入口） | R4 — 调用链冗余消除 |

只有两层都通过的函数，才最终确认为独立的外部入口。

## 4. 核心能力

系统回答三个问题：

| | 问题 | 方式 |
|:---|:---|:---|
| ① | 这个模块有哪些函数？ | R1 — 静态提取 + LLM 覆盖率补全 |
| ② | 哪些函数有外部输入？ | R3 — LLM 逐函数分析 + Judge 验证 |
| ③ | 有外部输入的函数中，哪些是总入口而非内部子步骤？ | R4 — 静态调用链建图 + 冗余消除 |

## 5. 架构

```
源文件清单 ──→ R1（函数提取+覆盖率）──→ R2（行号准确性）──→ R3（外部输入分析）×N
                    │                       │                    │
                    │ 函数列表写入 FuncDB     │ 行号修正          │ analysis + decision
                    ▼                       ▼                    ▼
                                                               CC（静态调用链建图）
                                                                    │
                                 R4（调用链冗余消除）×N ←────────────┘
                                 R5（单函数报告）×N
                                 R6（最终产物聚合，脚本化）

产物：functions.list + entry-details.json + final_report.md
```

### 5.1 六阶段流水线

系统提供两套流水线引擎：

| 引擎 | 文件 | 适用场景 |
|:---|:---|:---|
| **完整模式** | `engine.py` | 默认，所有函数经过完整 R3 Agent 分析 |
| **Lean 模式** | `lean_engine.py` | `api_filter_entry_judge=True` 时启用，在 R2 与 R3 之间插入 API_Filter 预筛 |

两套引擎的阶段定义一致，Lean 模式仅增加 API_Filter 预筛阶段。

每个阶段由 **Worker（执行分析）+ Judge（验证结论）** 双角色构成。Worker 负责分析并产出结论，Judge 以独立上下文验证结论的正确性。Judge 不通过时，Worker 带反馈重试，形成闭环修正。

```
R1-W → R1-J ──passed──→ 进入 R2
      └──failed──→ R1-W（带反馈重跑）

R2-J（先行验证）──passed──→ 进入 R3
      └──failed──→ R2-W（带反馈修正行号）→ R2-J

R3-W → R3-J ──passed──→ 进入 CC 等待
      └──failed──→ R3-W（带反馈重跑）

CC（纯静态建图，无 LLM）──completed──→ 解锁 R4

R4-W → R4-J ──passed──→ R5
      └──failed──→ R4-W（带反馈重跑）

R5-W → R5-J ──passed──→ R6
      └──failed──→ R5-W（带反馈重写报告）

R6（纯脚本聚合，无 LLM）→ 最终产物
```

#### R1 — 函数覆盖率（文件级）

**问题**：「这个源文件有哪些函数？」

先用 ctags 静态提取函数列表（含名称、签名、起止行），写入 FuncDB。再用可跳过的 gap 区间预筛（extern 声明块、注释块、struct/enum 定义等程序化确认不含函数体），剩余 gap 交由 LLM Worker 逐区间扫描，补充 ctags 遗漏的函数（如嵌套函数、宏展开后的函数）。Judge 验证函数列表完整性。

关键优化：gap 区间预筛（`_classify_gap`）可自动跳过 60-80% 的 gap，大幅减少 LLM 调用。

#### R2 — 行号准确性（函数级，J 先行）

**问题**：「ctags 标记的函数边界是否准确？」

Judge 先行：不依赖 Worker，直接用脚本 awk/sed 验证 start_line、end_line、花括号匹配。脚本无法确定时（花括号不匹配、首末行异常），再派 Worker 用 sed 定位正确行号并修正。Worker 仅按需触发。

脚本快速路径（R2 script）覆盖约 70-80% 的函数，仅在 body 与源文件不一致时回退到 LLM。

#### R3 — 外部输入分析（函数级，与 CC 并行）

**问题**：「这个函数是否有外部数据进入？数据从哪来？」

LLM Worker 读取函数体和签名，判断：
- `has_external_input`：是否有外部数据进入
- `tag`：P（被动回调）或 A（主动拉取）
- `taints`：污点变量列表（参数名 或 `recv@buf`）
- `taint_details`：每个污点的来源和路径描述
- `entry_role`：边界角色（boundary / callback / ipc_handler / dispatch_target）
- `decision`：keep（保留）或 filter（过滤）

Judge 验证：taints 非空（有参函数）、tag 合法、has_external_input 与 decision 自洽。

R3 与 CC 完全并行——R3 不需要调用链信息即可独立判断该函数是否有外部输入。

可选：`api_filter_entry_judge = True` 时，在 R2 与 R3 之间插入轻量 API_Filter（直接调用 LLM API，无 pi 子进程）。AF 判定非入口 → 直接跳过完整 R3 分析，减少 30-50% 的计算。

API_Filter 采用独立超时控制（每函数 `EA_API_FILTER_TIMEOUT_SECONDS`，默认 45s），超时函数保守保留（不漏报）。每次 Filter 调用的 LLM 对话历史写入独立 JSONL session 文件，支持审计回溯。

当启用 API_Filter 时，流水线引擎切换为 **LeanPipelineEngine**（`lean_engine.py`）——这是 `engine.py` 的并行变体，在 R2 与 R3 之间插入 API_Filter 阶段，其余阶段与完整模式一致。

#### CC — 静态调用链建图（模块级，无 LLM）

**问题**：「模块内函数之间的调用关系是怎样的？」

纯静态分析，不调用 LLM。扫描所有函数的 body 文本，用正则提取三种调用关系：
- `direct`：`FuncName(...)` 直接调用
- `ptr`：`handler = FuncName` 函数指针赋值 / 传参
- `extern_table`：extern 声明块中的 dispatch table 注册

结果写入 `callchain.db`（SQLite），支持 O(1) 可达性查询（传递闭包）。为 R4 提供调用链上下文。

#### R4 — 调用链冗余消除（函数级）

**问题**：「R3 判定有外部输入，但它是总入口还是内部子步骤？」

核心逻辑：如果 A 调用了 B，且 A 也是外部入口，那么 B 的外部输入实际来自 A，B 不是独立入口。R4-W 结合 CallchainDB，判断该函数是否有 R3-kept 的调用者。有五路快速路径：

| 路径 | 条件 | 结论 |
|------|------|------|
| ① A 类 | tag=A（主动读 I/O） | 直接 keep |
| ② P 类外部入口 | 无任何 R3-kept 调用者 | 直接 keep |
| ③ Deferred | 仅有 running 调用者 | 保守 keep（等 R6 重分类） |
| ④ 需 W+J | 有 R3-kept 调用者 | 进入 R4 W+J 循环 |
| ⑤ 保守 keep | CallchainDB 不可用 | 直接 keep（不丢漏） |

路径①②③⑤ 覆盖约 60-80% 的情况，无需 LLM；仅路径④触发完整 R4-W+J。

#### R5 — 单函数报告（函数级）

**问题**：「能为每个最终入口生成一份详细的分析报告吗？」

对 R4 确认 keep 的函数，LLM Worker 生成结构化 Markdown 报告，包含：函数用途、外部输入来源、污点参数详情、调用链关系。Judge 验证报告质量（字段完整、描述准确、格式规范）。

#### R6 — 最终产物聚合（模块级，脚本化）

**问题**：「如何将分散在各阶段的结论整合为可交付的最终产物？」

纯脚本，无 LLM。遍历所有 FuncDB，提取 `r3_decision=keep` 且 `r4_decision=keep/NULL` 的函数，生成：
- `functions.list`：外部入口的结构化清单（JSON，供 Binary Security 消费）
- `handler.list`：处理入口（内部入口，供前端展示）
- `entry-details.json`：全量入口详情（供前端消费）
- `final_report.md`：汇总分析报告（含 token 用量、耗时统计）

### 5.2 并发模型

```
asyncio.gather(
    _cc_phase(),                    ← 全局唯一，等 all_r2_done_event 后启动
    _file_pipeline(file_1),         ← 每个文件独立协程，文件间完全并发
    _file_pipeline(file_2),
    ...
)
```

每个 `_file_pipeline` 内部：R1-W → R1-J（文件级串行）→ `asyncio.gather(func_pipeline(func_1), func_pipeline(func_2), ...)`（函数间并发）。

每个 `func_pipeline` 内部：R2 → R3 → await CC → R4 → R5（函数内串行）。

R2 并发信号量（`EA_R2_CONCURRENCY`，默认 32）防止数百个函数同时提交 asyncio.to_thread 导致任务风暴。

### 5.3 同步信号

| 信号 | 触发条件 | 解锁对象 |
|------|----------|----------|
| `all_r2_done_event` | 所有文件 R1 完成 且 所有函数 R2 完成 | CC 开始建图 |
| `cc_done_event` | CC 建图完成 | 各函数 R4 解锁（各函数独立 await） |
| `asyncio.gather` 全部返回 | 所有文件流水线完成 | R6 脚本启动 |

### 5.4 数据存储

系统有三个核心数据库：

| 数据库 | 类型 | 粒度 | 职责 |
|--------|------|------|------|
| **FuncDB** | SQLite（WAL） | per-file | 函数信息（名称、签名、行号、body、分析结果、决策）的单一可信源 |
| **CallchainDB** | SQLite（WAL） | per-module | 调用图（节点、边、传递闭包、入口子树） |
| **ModuleDB** | SQLite | per-module | （已废除）模块级函数索引；改为遍历 FuncDB 聚合 |

FuncDB 的设计核心：避免 Agent 读取大文件（JSON 可达 1MB）时被 pi `read` 工具 50KB 截断。SQLite WAL 模式支持并发读写，64 个协程可同时 SELECT 不阻塞。

### 5.5 状态机

`PipelineState` 持久化到 `pipeline_state.json`，支持原子写入（mkstemp + rename），跟踪每个文件和函数在各阶段的执行状态（PENDING → RUNNING → PASSED / FAILED），支持重试和断点续跑。

三层状态嵌套：
```
PipelineState
  ├─ cc_state, r6_state
  └─ files: {file_hash: FileState}
       ├─ r1_w_state, r1_j_state
       └─ functions: {func_hash: FunctionState}
            ├─ r2_w/j_state
            ├─ r3_w/j_state, has_external_input, r4_decision
            ├─ r4_state, r4_decision, r4_j_state
            └─ r5_state
```

### 5.6 Skills 系统

Skills 是注入 LLM Agent 上下文的轻量级指令模块。Worker/Judge 启动前，引擎将对应 skills 复制到 stage 专属 `cwd/.pi/skills/`，Agent 按需加载。

| Skill | 使用者 | 用途 |
|-------|--------|------|
| `ea-output-format` | Worker | 输出格式自检（`<result>` 标签包裹） |
| `query-functions-db` | Worker/Judge | FuncDB 查询规范 |
| `ea-r1-judge-guide` | R1-Judge | 覆盖率验证三步核查 |
| `write-entry-list-json` | Worker | 写入 entry-list-merged.json |
| `write-functions-list` | Worker | 生成 functions.list |

### 5.7 置信度评分

每个入口函数经过 R3-W 分析后获得初始置信度分数（0.0-1.0），CC 建图后结合调用链信息修正。评分维度：

| 维度 | 权重 | 来源 |
|------|------|------|
| 基础分（has_external_input） | +0.35 | R3-W |
| 主动拉取型（tag=A，有 recv 证据） | +0.20 | R3-W |
| 代码证据行 | +0.08 | R3-W |
| R3-J 验证通过 | +0.15 | R3-J |
| 角色：boundary | +0.15 | R3-W |
| 角色：callback | +0.12 | R3-W |
| 无模块内调用者 | +0.15 | CC |
| 被 >3 个内部函数调用 | -0.10 | CC（惩罚） |

置信度分数不仅用于最后展示，也用于前端排序和下游消费方的优先级决策。

## 6. 服务架构

### 6.1 运行时角色

Entry Analyse 在 SecFlow 平台中以微服务形式运行（`secflow-app-entry-analyse`），支持三种运行时角色：

| 角色 | 入口 | 说明 |
|------|------|------|
| `api` | `main.py` → FastAPI Server | 接收任务、SSE 实时事件流、结果查询 |
| `worker` | WorkerService 后台循环 | 消费任务队列，执行流水线分析。启动前校验 `RUNTIME_ROLE_WORKER`，非 worker Pod 拒绝执行 |
| CLI | `cli.py` | 单次分析，Docker 容器内运行（`runtime_role=standalone`） |

### 6.2 智能体进程管理

Worker Pod 内智能体进程并发由 `AgentProcessSlotManager` 统一管理。单任务可吃满所在 Pod 的全部智能体槽位；多任务共享 FIFO 槽位队列。上限由 `EA_AGENT_PROCESS_LIMIT` 环境变量和配置页热生效。

Worker 心跳上报包含 `runtime_role` 标识，集群调度基于角色进行任务分配，确保分析任务只被路由到 worker Pod。

### 6.3 外部依赖

| 服务 | 用途 |
|------|------|
| MySQL | 任务状态、StageResult 索引、配置存储 |
| Redis | 任务租约续租、Pub/Sub 事件通知 |
| Nacos | 服务注册与配置中心（LLM Provider 配置同步） |
| Harbor | Docker 镜像仓库 |

## 7. 设计原则

| # | 原则 |
|:---|:---|
| 1 | **分工明确，独立验证** — Worker 负责分析，Judge 负责验证。Judge 拥有独立上下文，不做 Worker 的延伸，而是严格的事实核查 |
| 2 | **代码即 ground truth** — 行号、函数体、调用关系均以源文件为准，不以 Agent 推断为准。body 始终由 Python 从源文件提取，不由 LLM 生成 |
| 3 | **先脚本，后 LLM** — 能程序化确定的（gap 预筛、行号 awk 验证、调用链 R4 快速路径）优先脚本处理，LLM 仅做脚本无法覆盖的模糊判断 |
| 4 | **不允许漏报** — 超时、异常、脚本无法确定时默认保留（force-pass），不丢漏潜在入口。宁可多报，不可漏报 |
| 5 | **并发与独立** — 文件间完全并发、函数间并发（受限信号量）、CC 与 R3 完全并发。各函数流水线彼此隔离，互不等待 |
| 6 | **单一可信源** — FuncDB 是函数信息的唯一权威来源。不依赖中间 JSON 文件在阶段间传递数据（JSON 有截断风险） |
| 7 | **可追溯** — 每个阶段的 W/J 输出、session 对话历史、修正日志均持久化到磁盘和 MySQL，支持复盘和审计 |
| 8 | **策略可配置** — 各阶段最大重试轮次、并发上限、API_Filter 开启/关闭均可按任务配置，适应不同规模和精度的分析需求 |

## 8. 关键度量

| 指标 | 典型值 | 说明 |
|:---|:---|:---|
| 分析文件数 | 2-40 | 单模块 |
| 分析函数数 | 10-400+ | 单模块 |
| 最终入口数 | 3-15 | 通常为总函数数的 1-5% |
| 耗时 | 10-60 min | 取决于文件数、函数数、LLM 并发度 |
| R2 脚本覆盖 | 70-80% | 无需 LLM 的函数占比 |
| R4 快速路径覆盖 | 60-80% | 无需 W+J 的函数占比 |
| gap 预筛跳过 | 60-80% | 程序化确认的非函数 gap 占比 |
