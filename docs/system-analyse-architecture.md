# system-analyse 架构设计

## 1. 定位

system-analyse 是 SecFlow 分析流水线中的**固件安全威胁分析系统**。它接收 firmware-unpacker 解包后的文件系统树，基于多 Agent 流水线执行：**文件过滤 → 模块分类 → 精细化拆分 → STRIDE 威胁分析 → 汇总报告**，产出结构化的安全认知和按风险排序的模块清单。

系统不绑定特定固件类型：通过可配置的类型过滤（`analyse_targets`）和架构过滤（`binary_arch`），可适配任意嵌入式固件（路由器、交换机、IoT 设备等）的安全分析场景。

## 2. 挑战

固件安全分析面临三个核心矛盾：

**规模与深度的矛盾。** 一个典型的网络设备固件解包后包含 1000–3000 个文件，其中二进制（ELF/内核模块）可达数百个。逐一人工分析这些 ELF 的攻击面、依赖库和 STRIDE 威胁在时间上不可行。传统工具（如 `readelf`、`nm`）能提取符号表但无法推理安全语义，批量扫描规则又无法处理上下文的微妙性。

**精度与覆盖的矛盾。** 让 LLM 逐个分析所有文件精度高但成本巨大（千文件 × 分钟级推理 = 数十小时）；用正则/脚本粗略分类速度快但遗漏多。系统需要在"不错过"和"不浪费"之间找到平衡。

**错误传导的矛盾。** 多阶段流水线中，上游的分类错误会逐级放大——一个文件放错了模块，该模块的所有后续威胁分析都基于错误上下文。系统需要层层验证机制来截断错误传播。

system-analyse 的解法是**"确定性预处理 + LLM 语义决策 + Judge 独立校验"三层共振**：Python/Shell 脚本做无成本的批量预处理（格式识别、ELF 特征提取、文件预览），LLM 只在对安全有意义的决策点介入（模块划分、威胁判断），Judge 严格独立性保证每个决策可被外部验证。

## 3. 核心能力

系统回答四个问题：

| | 问题 | 方式 |
|:---|:---|:---|
| ① | 固件里有哪些安全相关的文件？ | Stage 0：六阶段确定性预处理——文件过滤 → 类型分类 → UNKNOWN 识别 → 目录探索 → 预扫描 → 全量预读 → 校验 |
| ② | 文件应如何组织为分析模块？ | Stage 1：Worker+Judge 多轮迭代，创建 modules/ 目录树，零遗漏铁律验证 |
| ③ | 每个模块的安全威胁是什么？ | Stage 2-3：模块精细化拆分 → STRIDE 威胁分析，预注入 ELF 符号消除 tool call |
| ④ | 整体安全态势如何？ | Stage 4：完整性检查 + 总报告生成 + 按风险排序的模块清单 |

## 4. 系统架构

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    system-analyse (FastAPI + uvicorn)                     │
│                                                                          │
│  ┌─────────────┐    ┌──────────────────┐    ┌────────────────────────┐  │
│  │   API 层     │    │  Orchestrator     │    │  服务层 (service/)      │  │
│  │  server.py   │───►│  orchestrator.py  │    │                        │  │
│  │  api/tasks   │    │  目录初始化        │    │  • runtime_bootstrap   │  │
│  │  api/prompts │    │  Pipeline 组装    │    │  • task_service        │  │
│  │  api/admin   │    │  错误处理 + 归档   │    │  • task_repository     │  │
│  └─────────────┘    └────────┬─────────┘    │  • worker_dispatcher    │  │
│                              │              │  • config_service       │  │
│                              ▼              │  • llm_provider_sync    │  │
│  ┌──────────────────────────────────────┐   │  • registry_service     │  │
│  │          Pipeline (pipeline/)         │   │  • self_reflection      │  │
│  │                                      │   └────────────────────────┘  │
│  │  Stage 0: 预处理 (7 子阶段)           │                               │
│  │  ├── FilterStage            文件过滤  │                               │
│  │  ├── TypeClassifyStage      类型分类  │                               │
│  │  ├── UnknownCheckerStage    UNKNOWN   │                               │
│  │  ├── ExploreStage           目录探索  │                               │
│  │  ├── PrescanStage           预扫描    │                               │
│  │  ├── PathGroupStage         路径分组  │                               │
│  │  ├── SubReaderStage         全量预读  │                               │
│  │  └── ValidateDetailsStage   校验      │                               │
│  │                                      │                               │
│  │  Stage 1: ClassifyStage         粗分类│                               │
│  │  Stage 1.5: SecurityFocusFilter   安全│                               │
│  │  Stage 2: RefineStage          细分类│                               │
│  │  Stage 3: AnalyseStage      STRIDE  │                               │
│  │  Stage 4: CompletenessCheck + Report│                               │
│  └──────────────────────────────────────┘                               │
│                                                                          │
│  ┌──────────────────────────────────────┐                               │
│  │  跨切面设施                             │                               │
│  │  • PipelineContext  全局共享状态       │                               │
│  │  • CheckpointManager 断点续跑         │                               │
│  │  • EvaluationRecorder 评估记录        │                               │
│  │  • AgentProcessHandle pi 进程管理     │                               │
│  │  • AgentCleanupService 进程清理       │                               │
│  │  • AgentRuntimeRegistry 运行时注册    │                               │
│  │  • AgentObservabilityService 可观测   │                               │
│  └──────────────────────────────────────┘                               │
└──────────────────────────────────────────────────────────────────────────┘
```

## 5. 流水线总览

```
固件文件系统 (/data/target, RO)
        │
   ┌────▼─────────────────┐
   │  Stage 0: 预处理      │  纯 Python/Shell，零 LLM
   │  7 子阶段             │  格式识别、文件过滤、ELF 特征提取、全量预读
   └────┬─────────────────┘
        │
   ┌────▼─────────────────┐
   │  Stage 1: 粗分类      │  Worker(step1_classify.md)
   │  W+J 多轮迭代         │  + Judge(step1_check_classify.md)
   │                       │  零遗漏铁律: Missing>0 → score=0
   └────┬─────────────────┘
        │
   ┌────▼─────────────────┐
   │  Stage 1.5: 安全过滤  │  按 security_focus_categories
   │                       │  过滤非安全维度模块
   └────┬─────────────────┘
        │
   ┌────▼─────────────────┐
   │  Stage 2: 细分类      │  主从模式: SubWorker 预读摘要
   │  并行 × parallel      │  + Master 细分决策 + Judge 校验
   │  _modules             │  全局完整性检查 + 补分类
   └────┬─────────────────┘
        │
   ┌────▼─────────────────┐
   │  Stage 3: STRIDE 分析 │  Python 预注入 ELF 符号(1次 LLM)
   │  并行 × parallel      │  Worker(step3_analyse.md)
   │  _modules             │  + Judge(step3_check_analyse.md)
   │                       │  [需要重新分类] → S2-redo → S3-redo
   └────┬─────────────────┘
        │
   ┌────▼─────────────────┐
   │  Stage 4: 最终报告    │  4a: 完整性检查
   │                       │  4b: Worker(step4_final_report.md)
   │                       │       + Judge(step4_check_report.md)
   └────┬─────────────────┘
        │
   /data/output/
   ├── flag = 1
   ├── final_report.md
   ├── modules.list
   └── modules/<mod>/
       ├── files.list
       └── module_report.md
```

### 5.1 Stage 0：六阶段确定性预处理

Stage 0 的设计哲学是**"能用脚本就不用 LLM"**——所有子阶段均无 LLM 参与，保证毫秒到分钟级完成。

| 子阶段 | 类 | 输入 | 输出 | 说明 |
|:---|:---|:---|:---|:---|
| S0.0 文件过滤 | `FilterStage` | 固件目录 | `filtered_files.txt` | 按类型（binary/source/config）和 ELF 架构过滤。先尝试 agent 引擎（pi agent 分类），失败回退到 Shell 脚本 |
| S0.1 类型分类 | `TypeClassifyStage` | `filtered_files.txt` | `file_catalog.json` + `unknown_files.txt` | Python 脚本识别文件类型：ELF 二进制读 e_machine，文本文件按扩展名归类 |
| S0.2 UNKNOWN | `UnknownCheckerStage` | `unknown_files.txt` | 类型回填 | 对 UNKNOWN 文件做二次判断，尝试 LLM 辅助识别 |
| S0.3 目录探索 | `ExploreStage` | 固件目录 | `keywords.txt` | Worker（可选 LLM）遍历目录结构，生成关键词提示 |
| S0.4 预扫描 | `PrescanStage` | `keywords.txt` | `keyword_summary.txt` | 多进程扫描 ELF 文件（magic 检测），词频统计 + 黑名单过滤 |
| S0.5 路径分组 | `PathGroupStage` | 文件路径列表 | 路径先验分组 | 基于目录结构做路径级聚合，辅助分类 |
| S0.6 全量预读 | `SubReaderStage` | `filtered_files.txt` | `details/<path>.json` | **Stage 2-3 的性能关键**：每个文件预读关键信息（ELF → `nm -D` 符号/`readelf -d` NEEDED/`strings head-50`；源码 → ctags/grep 函数名；文本 → 前 8KB 内容） |
| S0.7 校验 | `ValidateDetailsStage` | details 目录 | 校验报告 | 验证 details JSON 完整性，标记无效文件 |

### 5.2 Stage 1：粗分类（W+J 多轮迭代）

**职责**：将过滤后的文件集合划分为逻辑模块，创建 `modules/<name>/files.list`。

**核心机制**：

- **Worker（step1_classify.md）**：分析 `filtered_files.txt` + `keyword_summary.txt` + `details/` 预读数据，创建模块目录树
- **Judge（step1_check_classify.md）**：零遗漏铁律——Missing（未被归入任何模块的文件数）> 0 → 评分 = 0，不通过
- **classification 脚本化**：Worker 不是写模块列表，而是**编写 `classify_framework.sh` 中的 `classify_file()` 函数**。Judge 执行该函数获得实际分类结果，避免幻觉
- **多轮迭代**：不通过时注入 Judge 反馈 + `reflect_classify.md` 反思提示词，Worker 修正分类逻辑

### 5.3 Stage 2：细分类（主从模式 + 并行）

**职责**：对粗分类产生的模块做精细化拆分，处理大模块（文件数 > 20）。

**主从架构**：

```
Module (文件数 > SUB_WORKER_THRESHOLD):
  │
  ├── SubWorker × parallel_sub_workers
  │   ├── batch_1 (1-20)  → 5列摘要: 路径|类型|功能|标识|子模块建议
  │   ├── batch_2 (21-40) → 5列摘要
  │   └── batch_N          → 5列摘要
  │
  └── Master Worker (step2_refine.md)
      └── 读所有 SubWorker 摘要 → 细分决策（拆分/保留/合并）
          └── Judge (step2_check_refine.md)
              └── check_module.sh 快照对比验证
                  └── 通过 → 子模块入队列（可能再次细分）
```

**完整性保障**：
- **快照机制**：细分前保存 `files.list` 快照，Judge 执行 `check_module.sh` 对比快照与所有子模块文件并集
- **全局校验**：Stage 2 结束后 `filtered_files.txt` vs 所有 `files.list` 并集，缺失文件触发补分类（最多 3 轮）
- **孤儿目录修复**：Judge 评审前自动修复 `modules/` 下的空壳目录和孤儿文件

### 5.4 Stage 3：STRIDE 威胁分析

**职责**：对每个叶节点模块执行 STRIDE 安全分析。

**核心创新——文件预注入**：

```
传统方式 (旧):                   预注入方式 (新):
Worker open → read ELF          Python 预读 (nm/readelf/strings)
  → bash nm -D → 42.6 tool       → 注入 system_prompt
    calls/module                  ↓
  → 9 min/module                Worker 直接写 module_report.md
                                 (tools=["write"], 1次 LLM 调用)
                                 → 1.5 min/module（5-6× 加速）
```

预注入的 ELF 信息：
- **导出符号**：`nm -D` 前 300 个 → 对外攻击面
- **导入符号**：`nm -D` 前 150 个 → 危险函数调用（`system`/`memcpy`/`strcpy` 等）
- **依赖库**：`readelf -d NEEDED` → 安全库识别（`libssl`/`libcrypto` 等）
- **字符串**：`strings head-50` → 错误消息/协议字符串上下文

**重分类回溯**：
```
Stage 3 Worker → 发现 [分类问题]
         ↓
Stage 3 Judge → 确认 [需要重新分类]（严重性由 LLM 决定）
         ↓
modules_needing_reclassify 列表
         ↓
Stage 2-redo: 对问题模块重新细分
         ↓
Stage 3-redo: 仅处理新产生或 files.list 非空的模块
```

### 5.5 Stage 4：最终报告

**两阶段流程**：

1. **S4a 完整性检查**（`CompletenessCheckStage`）：Judge 验证所有模块都已分析，缺失模块回 Stage 2+3 补做
2. **S4b 总报告生成**（`FinalReportStage`）：Worker 读取所有 `module_report.md`，生成 `final_report.md`（STRIDE 汇总 + 暴露面评估 + 修复建议），Judge 评审报告质量

若 LLM 在写出报告前终止，系统自动生成兜底报告（程序汇总所有 `module_report.md` 的 risk_level 和 risk_score）。

## 6. Worker + Judge 循环机制

每个使用 LLM 的阶段共享相同的核心控制流：

```
                    ┌───────────────────────────────┐
                    │     W+J 轮次循环               │
                    │                               │
  ────────────────►  Worker 执行任务                 │
                    │   (session 持久, 保留上下文)    │
                    │        │                      │
                    │        ▼                      │
                    │   Judge 评审                   │
                    │   (无 session, 每轮全新)        │
                    │   parse_eval_md() 提取:        │
                    │     score / pass / feedback    │
                    │        │                      │
           ┌────────┤  pass=是 且 round≥min ────────►│──► 下一阶段
           │        │  pass=否 或 round<min          │
           │        │                               │
           │        │  注入 reflect_*.md 反思提示     │
           │        └───────────────┬───────────────│
           │                        │               │
           └────────────────────────┘               │
                    round++ 继续循环                 │
                    │                               │
                    │  round > max_rounds            │
                    │  → StageError（报警）           │
                    └───────────────────────────────┘

投票模式 (pass_mode):
  all       → 所有 Judge 全部通过
  majority  → 超半数 Judge 通过
  any       → 至少 1 个 Judge 通过（用于探索性阶段）
```

**关键设计决策**：

| 设计点 | Worker | Judge |
|:---|:---|:---|
| Session 管理 | `--session <file>` 持久化，跨轮保留上下文 | `--no-session` 无状态，每轮全新 |
| 工具集 | `read, bash, edit, write, grep, find` | `read, bash, grep, find`（只读） |
| 思考级别 | 可配置（off/medium/high） | 默认 off（快速评审） |
| 并发数 | 1 个（模块独占） | 可配 1-N 个（并行评审） |

## 7. Agent 运行时

### 7.1 Runner：pi RPC 进程管理

```
┌───────────────────────────────────────────────────────────┐
│                    runner.py                              │
│                                                           │
│  pi --mode rpc --session <file> [--model <m>]            │
│       ↑ stdin:  {"type":"prompt","message":"..."}        │
│       ↓ stdout: JSONL events (message_end 等)            │
│                                                           │
│  双层重试机制：                                            │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ 外层 — 进程级重试 (pi_max_retries, 默认 ∞)          │ │
│  │   进程拉起失败 / 崩溃 / SIGKILL → 重新拉起           │ │
│  │   致命错误: 401 Unauthorized / model not found       │ │
│  │   → 不重试，PiFatalError 终止流水线                  │ │
│  ├─────────────────────────────────────────────────────┤ │
│  │ 内层 — API 级重试 (agent_max_retries, 默认 100)     │ │
│  │   连接超时 / 限流 429 / 服务错误 5xx → 重试           │ │
│  │   固定退避: 3s → 5s → 10s → 15s → 30s (上限 30s)    │ │
│  │   502 特殊处理: 等待更长时间（模型过载信号）          │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                           │
│  卡死检测: 1800s 无 message_end → 检测 + 重启 (5次上限)   │
│  Context Window: 模型无响应 30min → COMPACTION 触发       │
└───────────────────────────────────────────────────────────┘
```

### 7.2 PiRpcClient 核心接口

| 能力 | 实现方式 |
|:---|:---|
| prompt 发送 + 流式回调 | `proc.stdin.write(json) → readline loop → stream_callback` |
| RPC mode 突破 ARG_MAX | prompt 经 stdin 输入，无命令行长度限制；system_prompt 经 `--append-system-prompt` 文件传入 |
| 进程保活 | `respawn()` 重新拉起 pi，保留 session 文件保证上下文不丢失 |
| 超时管理 | `threading.Timer` + `os.killpg(SIGKILL)` 进程组终止 |
| Token 统计 | `get_session_stats` RPC 获取 input/output/cache 统计 |
| 优雅关闭 | `SIGTERM → wait(10s) → SIGKILL` 带宽限期 |

## 8. 跨切面设计

### 8.1 PipelineContext：全局共享状态

```
PipelineContext 是流水线各阶段之间传递状态的唯一载体：

  ┌─────────────────────────────────────────┐
  │  配置: cfg (TaskConfig)                  │
  │  路径: workspace / output_dir / sess_dir │
  │        final_out_dir / flag_path         │
  │                                         │
  │  事件: emit (SwarmEvent)                 │
  │  Token: tokens (TokenUsage)              │
  │  评估: evaluator (EvaluationRecorder)    │
  │  续跑: checkpoint (CheckpointManager)    │
  │  取消: cancel_event (asyncio.Event)      │
  │                                         │
  │  Stage 0 输出:                           │
  │    filtered_files / filter_count         │
  │    file_catalog / unknown_files          │
  │    details_dir / classify_context_path   │
  │    prescan_summary                       │
  │                                         │
  │  Stage 1 输出: classified_modules        │
  │  Stage 2 输出: refined_modules           │
  │  Stage 3 输出: analysed_modules          │
  │             modules_needing_reclassify   │
  │             soft_failed_modules          │
  │  Stage 4 输出: final_report_path         │
  └─────────────────────────────────────────┘
```

### 8.2 Checkpoint：断点续跑

```
workspace/.checkpoint/
├── s0_filter.done
├── s0_type_classify.done
├── s0_explore.done
├── ...
├── s1_classify.done
├── s2_refine.done
├── s2_modules/
│   ├── auth.done          ← 模块级续跑
│   ├── network.done
│   └── crypto.done
├── s3_analyse.done
├── s3_modules/
│   ├── auth.done
│   └── network.done
└── s4_report.done
```

- **原子写入**：tmp → rename 防止脏标记
- **模块级粒度**：S2/S3 支持模块级 checkpoint，失败模块可单独重做
- **脏检测**：checkpoint 存在但产物（files.list / module_report.md）无效时自动清理并重建
- **Resume 语义**：restart = 清空所有 checkpoint 重新开始；resume = 增量续跑已完成模块

### 8.3 EvaluationRecorder：评估体系

每个 Worker+Judge 轮次记录结构化评估数据：

```json
{
  "module_name": "network",
  "stage": "analyse",
  "stage_round": 2,
  "status": "passed",
  "worker": {
    "model": "zai-org/GLM-5",
    "session_file": "analyse/network.jsonl",
    "token_usage": {"input": 12345, "output": 2345, "cost": 0.12}
  },
  "judges": [
    {"judge_id": "j0", "score": 85, "passed": true, "token_usage": {...}}
  ],
  "passed_by_vote": true,
  "module_completed": true
}
```

### 8.4 Self-Reflection：自省分析

任务完成后自动触发的后台分析：

- 从 `evaluation_summary.json` 和 round JSON 收集执行数据
- 聚合 Stage 统计（每阶段耗时/token/通过率）
- 提取 Top-N token 消耗轮次
- 收集失败轮次的 Judge feedback
- 调用 LLM 生成 Markdown 分析报告（优化建议、瓶颈识别）

### 8.5 模块失败宽容策略

`continue_on_module_failure=true`（默认）时，单个模块分析失败不会中止整个流水线。失败的模块记录到 `soft_failed_modules`，在最终报告中标记为"分析未完成"。

## 9. 运行时角色

系统支持三种运行时角色（通过 `SECFLOW_SA_ROLES` 控制）：

| 角色 | 职责 | 说明 |
|:---|:---|:---|
| `api` | REST API + 任务创建/查询 | 对外暴露 HTTP 接口 |
| `manager` | 任务编排 + 生命周期管理 | 负责任务的创建、执行调度和状态跟踪 |
| `runner` | Worker 执行 | 消费任务队列，执行 pipelining。**单槽执行**（同时最多 1 个分析任务），每任务启动前通过 `AgentCleanupService` 清理残留 Agent 进程 |

> **架构演进**：runner 角色已改为单槽模式——`_resolve_worker_task_concurrency()` 固定返回 `1`。多任务并发通过水平扩展 runner Pod 数量实现。旧版基于 `cleanup_orphan_pi_processes` 的进程清理已被 `AgentCleanupService` + `AgentRuntimeRegistry` 替代，后者通过 `/proc` 扫描 + session 文件匹配实现更精准的进程归属判断。

### 9.1 Agent 进程生命周期管理

系统通过三个协作组件管理 pi Agent 子进程的完整生命周期：

| 组件 | 文件 | 职责 |
|:---|:---|:---|
| **AgentRuntimeRegistry** | `agent_runtime_registry.py` | 内存级 Agent 运行时注册表：以 session 文件路径为 key，记录 PID、启动时间、最近活动时间 |
| **AgentObservabilityService** | `agent_observability.py` | `/proc` 扫描 + 进程快照构建：识别 pi/claude/codex/opencode 进程，匹配 session 归属，检测孤儿进程 |
| **AgentCleanupService** | `agent_cleanup.py` | 任务级进程清理：扫描 `/proc` 中残留的 Agent 进程，SIGTERM → SIGKILL 两级终止；清理结果写入可观测快照 |

```
Agent 进程生命周期:
  register_agent_runtime(session_file, pid)   ← pi 子进程启动时注册
         │
  touch_agent_runtime(session_file)           ← 每次 prompt 完成时更新活跃时间
         │
  AgentObservabilityService.build_snapshot()  ← 周期性扫描 /proc
         │
         ├── 匹配成功 → 更新活跃状态
         └── 超过 RUNTIME_ACTIVITY_STALE_SECONDS 无活动 → 标记为 orphan
                │
  AgentCleanupService.cleanup(task_owner)     ← 任务启动前/异常时调用
         │
         ├── 收集归属当前 worker 的残留进程
         ├── SIGTERM → 等待 → SIGKILL
         └── 幸存进程数 > CRITICAL_SURVIVOR_THRESHOLD → 告警
```

**关键设计**：
- **Session 归属**：通过解析 `/proc/{pid}/cmdline` 中的 `--session` 参数匹配进程到具体 session 文件，精准判断进程归属（而非粗粒度的进程名匹配）
- **双阈值控制**：`RUNTIME_ACTIVITY_STALE_SECONDS`（默认 120s）判断进程是否失活；`ORPHAN_PROTECTION_SECONDS`（默认 120s）控制孤儿进程的保护窗口
- **幸存告警**：清理后仍存活的进程数超过 `CRITICAL_SURVIVOR_THRESHOLD`（默认 3）时触发告警，防止僵尸 Agent 进程积累

## 10. 安全维度过滤

Stage 1.5 (`SecurityFocusFilterStage`) 根据 `security_focus_categories` 配置过滤非安全维度的模块：

```
security_focus_categories: ["auth", "crypto", "network", "access_control"]

  S1 粗分类产出 → S1.5 安全过滤
    auth 模块     → ✓ 保留（直接实现认证）
    crypto 模块   → ✓ 保留（直接实现加密）
    logging 模块  → ✗ 排除（辅助功能，非安全维度）
    ui 模块       → ✗ 排除（UI 层，非安全维度）
```

安全维度通过 `SECURITY_CATEGORIES` 字典定义，每个维度包含 `name`、`desc`、`includes`（应包含的文件示例）和 `boundary_note`（边界判断规则）。这些规则动态注入 Worker 和 Judge 的 system prompt，不依赖硬编码逻辑。

## 11. 目录结构

```
{output_dir}/{task_id}/
├── output/                     ← 最终交付件
│   ├── flag                   ← 1=成功 / 0=失败
│   ├── final_report.md        ← 总安全报告
│   ├── modules.list           ← 按风险排序的模块名
│   └── modules/               ← 各模块产物（软链接/拷贝）
│       └── <mod>/
│           ├── files.list     ← 模块文件清单
│           └── module_report.md ← STRIDE 分析
│
├── run/                        ← 中间产物
│   ├── workspace/
│   │   ├── target/            ← 固件目录（软链接）
│   │   ├── filtered_files.txt
│   │   ├── keyword_summary.txt
│   │   ├── details/           ← 文件预读 JSON
│   │   │   └── <path>.json
│   │   ├── modules/           ← 模块目录树
│   │   ├── judge_output/      ← Judge 评审文件
│   │   ├── .checkpoint/       ← 断点续跑标记
│   │   ├── deleted.list       ← 已确认排除文件
│   │   └── .pi/settings.json  ← pi compaction 配置
│   ├── sessions/              ← Agent session 文件
│   │   └── analyse/
│   │       └── <mod>.jsonl
│   ├── evaluation_summary.json
│   ├── round_*.json           ← 各轮次评估记录
│   └── result.json            ← 任务执行结果
│
└── events/                     ← 任务事件流
```

## 12. 配置模型

### 分析类型与架构

```json
{
  "analyse_targets": ["binary", "source"],
  "binary_arch": ["arm", "aarch64"],
  "security_focus_categories": ["auth", "crypto", "network"],
  "module_granularity": "fine"
}
```

| 配置 | 可选值 |
|:---|:---|
| `analyse_targets` | binary / source / script / config / firmware / crypto / database / web / document / all |
| `binary_arch` | arm / aarch64 / x86 / x86_64 / mips / ppc / ppc64 / riscv / s390 / all |
| `module_granularity` | fine（细粒度）/ medium（中粒度）/ coarse（粗粒度）|

### 阶段循环控制

```json
{
  "stages": {
    "classify":    {"min_rounds": 1, "max_rounds": -1, "pass_mode": "all"},
    "refine":      {"min_rounds": 1, "max_rounds": -1, "pass_mode": "all"},
    "analyse":     {"min_rounds": 1, "max_rounds": -1, "pass_mode": "all"},
    "final_check": {"min_rounds": 1, "max_rounds": -1, "pass_mode": "all"}
  }
}
```

### 并行控制

```json
{
  "parallel_modules": 2,
  "parallel_sub_workers": 2
}
```

`parallel_modules=2, parallel_sub_workers=2` 时最大并发 = 4 个 LLM 调用。S2 SubWorker 先并行预读，然后 Master Worker 串行决策。

### 重试配置

| 配置 | 默认 | 说明 |
|:---|:---|:---|
| `agent_max_retries` | 100 | API 错误重试上限，-1=无限 |
| `agent_retry_delay` | 30s | 首次重试等待秒，指数退避 |
| `pi_max_retries` | -1 | pi 进程崩溃重试上限 |
| `pi_retry_delay` | 10s | pi 进程重试首次等待秒 |

## 13. API 设计

所有 API 遵循 SecFlow 分析服务统一范式：

| 方法 | 路径 | 用途 |
|:---|:---|:---|
| `POST` | `/api/app/system-analyse/tasks` | 提交分析任务 |
| `GET` | `/api/app/system-analyse/tasks` | 任务列表 |
| `GET` | `/api/app/system-analyse/tasks/{id}` | 任务详情 |
| `POST` | `/api/app/system-analyse/tasks/{id}/cancel` | 取消任务 |
| `POST` | `/api/app/system-analyse/tasks/{id}/restart` | 重新运行 |
| `GET` | `/api/app/system-analyse/tasks/{id}/stream` | SSE 事件流 |
| `GET` | `/api/app/system-analyse/health` | 健康检查 |
| `POST` | `/api/app/system-analyse/generate-prompt` | 根据路径生成 prompt |
| `CRUD` | `/api/app/system-analyse/prompts/*` | Prompt 模板管理 |
| `GET/PUT` | `/api/app/system-analyse/config` | 项目配置 |

## 14. 设计原则

| # | 原则 |
|:---|:---|
| 1 | **确定性优先，AI 只在语义决策点介入** — Stage 0 七个子阶段全部无 LLM，用 Python/Shell 做批量预处理，将 LLM 算力集中在 S1-S4 的模块划分和安全推理 |
| 2 | **预注入消除 tool call** — Stage 3 将 ELF 符号/依赖/字符串预注入 system_prompt，将单模块分析从 42.6 次 tool call 降至 1 次 LLM 调用，性能提升 5-6 倍 |
| 3 | **Judge 独立校验，截断错误传导** — Judge 无 session、无上下文记忆、只读工具，每次评审从零开始审视产物，上游分类错误不会污染下游判断 |
| 4 | **零遗漏铁律** — 所有 Judge 统一采用 Missing > 0 → score = 0 的评分规则，多阶段全局校验确保无文件被遗漏 |
| 5 | **模块级断点续跑** — S2/S3 支持模块级 checkpoint，失败模块可单独重做而不影响已完成模块，支持超大规模固件分次分析 |
| 6 | **分类逻辑可审计** — S1 的 Worker 不是写分类结果，而是编写可执行的 `classify_file()` 函数，Judge 运行该函数做快照对比验证 |
| 7 | **主从并行，弹性伸缩** — S2 大模块（>20 文件）自动切换主从模式：SubWorker 并行预读摘要，Master 集中决策 |
| 8 | **失败宽容，全局推进** — 默认单模块失败不中止流水线（`continue_on_module_failure=true`），在最终报告中标记未完成模块 |
| 9 | **自省驱动持续改进** — 任务完成后自动触发自省分析，评估各阶段效率/成本/质量，生成优化建议 |
| 10 | **架构可配置，不绑定固件** — 类型过滤、架构过滤、安全维度、模块粒度均通过 JSON 配置驱动，无需修改代码即可适配不同固件 |

## 15. 与 SecFlow 流水线的集成

system-analyse 是 binary-security 端到端流水线的第二个阶段：

```
firmware-unpacker (解包)
    │ 产物: output/ 文件系统树 + summary.md
    ▼
system-analyse (模块分类 + STRIDE 威胁分析)
    │ 产物: modules/*/module_report.md + final_report.md + modules.list
    ▼
binary-to-source (二进制溯源)
    │ 以 S1/S2 产出的 modules/ 目录树为输入
    ▼
entry-analyse → dataflow-analyse → dataflow-vuln-scan
```

通过 `parent_project_id`、`parent_task_id`、`parent_stage_name` 等字段与 binary-security 编排器联动。

## 16. 性能参考（实测 NE8000 固件，1157 个 AArch64 ELF）

| 阶段 | 模块数 | 并行数 | 耗时 |
|------|--------|--------|------|
| S0（过滤 + 探索 + 预扫描 + 全量预读） | — | 1 | ~11 min |
| S1（粗分类） | ~18 顶层模块 | 1 | ~15 min |
| S2（细分类） | ~200 子模块 | 2 | ~2 h |
| S3（分析，预注入优化后） | 202 | 2 | ~3 h |
| S4（报告） | — | 1 | ~20 min |
| **总计** | | | **~6 h** |

> S3 优化前耗时 ~13 h（平均 42.6 tool calls/模块）。预注入优化将每模块 LLM 调用从 42.6 次降至 1 次，耗时从 ~3.8 min/模块降至 ~0.9 min/模块。

---
> 文档版本：`v2.1` @ `5e4b6467` · 子模块 `d338e4a`（2026-06-05）
