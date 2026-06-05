# firmware-unpacker 架构设计

## 1. 定位

firmware-unpacker 是 SecFlow 分析流水线中的**固件解包微服务**。它接收原始固件镜像（bin/img/zip/tar 等），将其解包为可分析的文件系统树，产出结构化元数据（format_id / family_id / summary / reason），供下游 system-analyse 消费。

服务不绑定单一解包策略：确定性工具链（tar / unsquashfs / binwalk / jefferson 等）、用户编写的 Python 解包工具、以及 LLM Agent 驱动的语义解包三种引擎按优先级级联执行。每次成功解包自动沉淀为技能（skill），失败经验通过进化引擎反哺工具库。

## 2. 挑战

固件解包是一个"表面上简单、实际上极难"的问题：

**格式碎片化**。固件镜像不是标准文件格式——它可能是原始 flash dump、多层嵌套压缩、专有文件系统头、甚至厂商自定义的拼接格式。仅依靠 magic bytes 和文件扩展名无法覆盖真实世界场景。

**工具链不可靠**。binwalk、jefferson、unsquashfs 等工具只能覆盖已知格式，且同一格式的不同变种（加密 squashfs、定制 ubi layout）会导致工具静默失败——行为上无报错，输出上为空目录。

**经验无法沉淀**。每次成功解包依赖安全工程师的即时判断和手工命令行操作，这些知识随任务结束而消失。下一个人面对同样的固件变种时从零开始。

firmware-unpacker 的解法是三层级联引擎：确定性工具做第一道快速筛选，匹配的 Python 工具做第二道精确打击，LLM Agent 做第三道兜底和未知格式推理。每次成功的策略自动记录为可复用的 skill，失败的 skill 进入进化循环。

## 3. 核心能力

系统回答三个问题：

| | 问题 | 方式 |
|:---|:---|:---|
| ① | 这是什么格式的固件？ | 确定性格式检测 → 特征提取（magic / ext / binwalk signatures）→ family_id 计算 |
| ② | 如何正确解包？ | 三层级联引擎：规则工具链 → 匹配的 Python 工具 → LLM Agent 递归推理 |
| ③ | 怎样让下一次更快？ | 解包成功自动生成 skill → 多任务复用 → 失败 skill 进入进化引擎迭代改良 |

## 4. 系统架构

```
┌────────────────────────────────────────────────────────────────────┐
│                    firmware-unpacker (FastAPI)                      │
│                                                                    │
│  ┌──────────────────────┐  ┌──────────────────────────────────┐   │
│  │   API Layer          │  │   Background Runtime             │   │
│  │   (entrypoint.py)    │  │   (runtime.py)                   │   │
│  │                      │  │                                  │   │
│  │  • Task CRUD         │  │  ┌────────────┐ ┌─────────────┐ │   │
│  │  • Auth check        │  │  │ Scheduler  │ │ Dispatcher  │ │   │
│  │  • Menu registry     │  │  │ (assign    │ │ (single-    │ │   │
│  │  • Metrics/Health    │  │  │  tasks to  │ │  slot, max  │ │   │
│  └──────────┬───────────┘  │  │  workers)  │ │  1 task)    │ │   │
│             │              │  └─────┬──────┘ └──────┬──────┘ │   │
│  ┌──────────▼───────────┐  │        │               │         │   │
│  │   Shared Database    │◄─┼────────┴───────────────┘         │   │
│  │   (model.py)         │  │  Task Queue (MySQL)              │   │
│  └──────────────────────┘  │  assign / dispatch / lease       │   │
│                            │                                  │   │
│                            │  ┌────────────────────────────┐ │   │
│                            │  │  Agent Sanitizer           │ │   │
│                            │  │  (agent_sanitizer.py)      │ │   │
│                            │  │  • pre-run cleanup (/proc) │ │   │
│                            │  │  • post-run cleanup        │ │   │
│                            │  └────────────────────────────┘ │   │
│                            │                                  │   │
│                            │  ┌────────────────────────────┐ │   │
│                            │  │  Cleanup Worker            │ │   │
│                            │  │  • skill generation        │ │   │
│                            │  │  • workspace cleanup       │ │   │
│                            │  │  • evolution loop          │ │   │
│                            │  └────────────────────────────┘ │   │
│                            └──────────────────────────────────┘   │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │                   Unpacking Engine (unpacker_engine.py)       │ │
│  │                                                              │ │
│  │  Stage 1: Preprocess (确定性规则工具链)                       │ │
│  │  ├── 格式检测 (magic bytes + ext)                             │ │
│  │  └── 工具尝试: tar → zip → squashfs → gzip → bz2 → xz → ... │ │
│  │                                                              │ │
│  │  Stage 2: Feature Extract + Tool Match                       │ │
│  │  ├── binwalk 签名扫描                                        │ │
│  │  ├── family_id 计算                                          │ │
│  │  └── Dispatcher 规则匹配 → Python 工具选择                    │ │
│  │                                                              │ │
│  │  Stage 3: Tool Match Execution (Python 工具执行)              │ │
│  │  ├── 子进程运行 Python 解包脚本                               │ │
│  │  ├── 评审校验 (tool-level review)                             │ │
│  │  └── 失败 → 回退到 LLM 解包 (fallback_to_llm)                │ │
│  │                                                              │ │
│  │  Stage 4: LLM Unpack (Worker + Judge 迭代)                   │ │
│  │  ├── Executor Agent: 基于 pi RPC 的语义解包                   │ │
│  │  │   • Round 1: 初始解包尝试                                  │ │
│  │  │   • Round N: 注入 Judge feedback → 重新解包                │ │
│  │  ├── Reviewer Agent: 独立校验解包完整性                        │ │
│  │  ├── Recursive Expand (每轮后): 确定性递归展开中间产物         │ │
│  │  └── 默认 max_retries=3 轮迭代                                │ │
│  │                                                              │ │
│  │  Stage 5: Cleanup + Skill Generation                         │ │
│  │  ├── Cleaner Agent: 清理冗余文件                              │ │
│  │  ├── Skill Author Agent: 自动生成解包策略文档                  │ │
│  │  └── 产物规范化: summary.md / reason.md                      │ │
│  └──────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────┘
```

## 5. 运行时模式

服务支持五种运行时角色，通过 `FIRMWARE_UNPACKER_RUNTIME_ROLE` 环境变量控制：

| 角色 | 职责 | 部署形态 |
|:---|:---|:---|
| `api` | FastAPI HTTP 服务，提供任务 CRUD、认证、菜单注册 | 独立 Pod（2 replicas） |
| `scheduler` | 扫描 PENDING 任务，分配给空闲 dispatcher worker；回收孤儿任务 | 独立 Pod（1 replica） |
| `dispatcher` | **单槽执行**（同时最多 1 个任务）：接收 scheduler 分配的任务，启动子进程执行 | 可水平扩展多 Pod |
| `cleanup-worker` | 工作目录清理 + 技能生成 + 进化循环 | 独立 Pod（1 replica） |
| `all` | 遗留兼容模式：同时承担 dispatcher + scheduler + cleanup 职责 | 单 Pod 调试用 |

> **架构演进**：旧版的 `worker` 角色（线程池并发执行）已被废弃。`dispatcher` 现在是纯粹的单槽执行器——`_runtime_max_concurrent()` 固定返回 `1`，每个 dispatcher Pod 同时只运行一个解包任务。多任务并发通过水平扩展 dispatcher Pod 数量实现，而非 Pod 内线程池。

```
                         ┌──────────────┐
                         │   api Pod    │  HTTP 请求处理
                         │   (×2)       │  任务提交 + 状态查询
                         └──────────────┘
                                │
                         ┌──────▼──────────┐
                         │  scheduler Pod  │  扫描 PENDING 任务
                         │     (×1)        │  分配给空闲 dispatcher
                         └──────┬──────────┘
                                │ Assign (shared DB)
           ┌────────────────────┼────────────────────┐
           │                    │                    │
    ┌──────▼──────┐    ┌──────▼──────┐    ┌───────▼─────────┐
    │ dispatcher-1│    │ dispatcher-2│    │ cleanup-worker  │
    │ single-slot │    │ single-slot │    │ skill gen +     │
    │ max=1 task  │    │ max=1 task  │    │ evolution loop  │
    └─────────────┘    └─────────────┘    └─────────────────┘
```

- **Dispatcher 单槽执行**：`_runtime_max_concurrent()` 固定返回 `1`，确保每个 Pod 的 Agent 进程不互相干扰
- **Scheduler 任务分配**：scheduler 独立循环 `_scheduler_loop()`，将 PENDING 任务显式分配给空闲 dispatcher（`ASSIGNED` 状态），而非 dispatcher 自行争抢
- **Agent 进程清理**：每个 dispatcher 在启动任务前执行 `agent_sanitizer.pre-run cleanup`（扫描 `/proc` 清理残留 pi/codex/claude/opencode 进程），任务结束后执行 `post-run cleanup`
- **心跳与状态**：Worker 实例维护完整运行时状态（`starting → idle → busy → draining → dead`），心跳同步 `active_tasks` / `running_task_id` / `state`

## 6. 解包引擎：三层级联

解包引擎的核心设计理念是**"确定性优先，AI 兜底"**——不是一个模型解决所有问题，而是让每个层级处理自己擅长的部分。

```
         固件镜像
            │
    ┌───────▼────────   确定性规则工具链（preprocess.py）
    │  Stage 1       │
    │  magic + ext   ├── 成功 ──→ 返回
    │  tar/zip/gzip  │
    │  squashfs/jffs2│
    └───────┬────────   失败
            │
    ┌───────▼────────   特征匹配引擎（tool_dispatcher.py）
    │  Stage 2-3     │
    │  binwalk 特征  ├── 命中 ──→ Python 工具执行 → 评审
    │  family_id     │              │
    │  Dispatcher    │         失败/评审不通过
    └───────┬────────              │
            │        ◄─────────────┘
    ┌───────▼────────   LLM Agent 引擎（unpacker_engine.py）
    │  Stage 4       │
    │  Executor      │
    │  + Reviewer    ├── Worker × 1 + Judge × 1 迭代
    │  + Recursive   │   最大 3 轮，每轮后递归展开中间产物
    │    Expand      │
    └───────┬────────
            │
    ┌───────▼────────
    │  Stage 5       │  Cleanup + Skill Generation
    └────────────────┘
```

### 6.1 Stage 1：确定性规则工具链（`preprocess.py`）

纯规则驱动、不涉及 AI。按优先级依次尝试 20+ 种命令行工具：

- **压缩格式**：tar / gzip / bzip2 / xz / zstd / lzop / lzma / 7z / cab
- **文件系统**：squashfs / cpio / romfs / cramfs / jffs2 / ubi / ubifs / yaffs
- **备用**：binwalk -eM --run-as=root（通用的递归提取）

每种工具执行后检查输出目录是否存在且非空。成功后直接返回，跳过后续所有阶段。

### 6.2 Stage 2-3：特征匹配 + Python 工具执行

#### 6.2.1 特征提取（`extract_firmware_features`）

- **格式检测**：`detect_format()` 读取文件头 16 字节 magic，结合文件扩展名推断格式
- **binwalk 签名**：调用 `binwalk -B` 获取嵌入式签名特征（如 "uImage header"、"squashfs filesystem"）
- **family_id 计算**：基于 `fmt + ext + magic_hex` 生成确定性家族标识

#### 6.2.2 Dispatcher 规则匹配（`tool_dispatcher.py`）

Dispatcher 是特征到工具的映射表（`dispatcher_rules.json`）：

```json
{
  "version": 1,
  "rules": [
    {
      "id": "rule-xxx",
      "enabled": true,
      "conditions": {
        "magic_hex": "48445230",
        "ext": ".img"
      },
      "tool_id": "huawei_hdr_tool",
      "tool_version": 3,
      "priority": 10
    }
  ]
}
```

匹配逻辑：遍历所有 `enabled` 规则，`conditions` 全部满足则命中。支持 `magic_hex`、`ext`、`binwalk_sigs` 等多条件组合匹配。

#### 6.2.3 工具执行

命中的工具是以 Python 脚本形式存储的（位于 `tools/active/` 目录），每个工具包含 metadata 注释头：

```python
# name: huawei_hdr_tool
# format_id: huawei-hdr-firmware
# extensions: .img, .bin
# magic_hex: 48445230
# keywords: huawei, hdr, firmware
# binwalk_sigs: uImage header, Huawei

def main(manifest_path: str) -> int:
    """工具入口：读取 task.json，解包固件到 output/"""
    ...
```

工具通过子进程执行：`python tool.py task.json`，通过环境变量传递输入/输出路径。执行完成后由 Reviewer Agent 做 tool-level 评审——验证输出是否完整有意义。

若工具执行成功但评审不通过，或工具执行失败，则 `fallback_to_llm = True`，进入 Stage 4。

### 6.3 Stage 4：LLM Agent 解包（Worker + Judge 迭代）

这是处理未知格式和复杂固件的核心引擎。

#### 6.3.1 角色定义

| 角色 | Agent 定义文件 | 系统提示词 | 职责 |
|:---|:---|:---|:---|
| **Executor** | `firmware-unpacker.md` | `unpack-firmware.md` / `retry-firmware-unpack.md` | 执行解包操作：分析固件结构，选择工具，执行命令 |
| **Reviewer** | `firmware-unpack-reviewer.md` | `review-firmware-llm-unpack.md` | 独立验证：检查输出目录完整性、格式正确性、文件数量合理性 |
| **Cleaner** | `firmware-extract-cleanup.md` | `cleanup-firmware.md` | 清理收尾：删除中间文件、整理目录结构、移除冗余产物 |
| **Skill Author** | `firmware-skill-author.md` | `author-firmware-skill.md` | 知识沉淀：根据成功解包经验生成可复用的策略文档 |

#### 6.3.2 Worker + Judge 迭代循环

```
Round 1:
  Executor.prompt(unpack-firmware.md)
    → 分析固件，执行命令，产出文件
  Recursive Expand (递归展开中间产物)
  Reviewer.prompt(review-firmware-llm-unpack.md)
    → 评审: PASS or FAIL

Round 2 (if FAIL):
  Executor.prompt(retry-firmware-unpack.md + Judge feedback)
    → 注入评审反馈，重新执行
  Recursive Expand
  Reviewer.prompt → PASS or FAIL

...

Round N (max_retries=3):
  最终评审 → 记录 round_result.json
```

**关键设计**：
- **每轮后递归展开**：LLM 可能产出压缩包中间产物，每轮 Worker 完成后，`_run_recursive_expand()` 对输出目录做确定性递归展开（tar/zip/gzip/7z 等），直到无新文件或达到最大轮数
- **Session 复用策略**：Executor 默认复用 session（跨轮保留上下文），Reviewer 默认不复用（避免上一轮失败结论污染新一轮评审）
- **取消传播**：`cancel_check` 回调链贯穿整个引擎，取消信号可随时中断正在进行中的 Agent 调用

### 6.4 Stage 5：清理 + 技能生成

解包评审通过后：
1. **Cleaner Agent** 执行清理收尾，删除临时文件、整理目录结构
2. **Skill Author Agent** 自动生成解包策略文档（Markdown），包含 format_id、keywords、解包步骤
3. 文档保存为 **candidate skill**，经过 `promotion_threshold`（默认 5）次成功复用后自动提升为 **active skill**

## 7. PiRpcClient：AI Agent 的 stdin/stdout 通信层

`PiRpcClient` 是 pi coding agent 的 JSON-RPC 封装，通过子进程 stdin/stdout 进行双向通信。

```
┌──────────────────────────────────────────────────┐
│                  PiRpcClient                      │
│                                                  │
│  ┌────────────┐       stdin (JSON)       ┌─────┐ │
│  │   Python   │ ─────────────────────────►│     │ │
│  │   caller   │                          │ pi  │ │
│  │            │ ◄─────────────────────────│ CLI │ │
│  └────────────┘       stdout (JSON)       └─────┘ │
│                                                  │
│  核心能力:                                         │
│  • Prompt 发送 + 流式事件回调 (stream_callback)    │
│  • 超时控制 (SIGKILL process group)               │
│  • 自动重试 (超时重试 + busy 重试 + 进程崩溃重试) │
│  • Session 管理 (创建/复用/索引)                  │
│  • LLM Provider 隔离 (per-task agent dir)         │
│  • Token 统计 (get_token_stats)                   │
│  • 优雅关闭 (SIGTERM → wait → SIGKILL)            │
└──────────────────────────────────────────────────┘
```

### 7.1 Provider 隔离

每个任务可以为不同 Agent 角色绑定不同的 LLM provider 和 model：

| 角色 | 配置键 (provider) | 配置键 (model) |
|:---|:---|:---|
| executor | `llm_config_file_key_executor` | `llm_model_executor` |
| reviewer | `llm_config_file_key_reviewer` | `llm_model_reviewer` |
| cleaner | `llm_config_file_key_cleaner` | `llm_model_cleaner` |
| skill_author | `llm_config_file_key_skill_author` | `llm_model_skill_author` |
| skill_executor | `llm_config_file_key_skill_executor` | `llm_model_skill_executor` |
| evolution_improver | `llm_config_file_key_evolution_improver` | `llm_model_evolution_improver` |

Provider 配置支持两种来源：
1. **任务级绑定快照** (`llm_binding_snapshot`)：由上游 binary-security 在创建任务时透传，确保整个分析链的 provider 一致
2. **服务级配置**：从数据库 `service_configs` 表读取，作为默认值

### 7.2 超时与重试

- **单次 Agent 输入超时**：`agent_run_timeout_seconds`（默认 3600s）
- **超时后自动重试**：`agent_timeout_retry_enabled`（默认 true），`agent_timeout_max_retries`（默认 3，-1=无限）
- **busy 重试**：当 pi 返回 "already processing" 时自动 drain 当前 turn 并重试（最多 2 次）
- **进程崩溃重试**：pi 子进程异常退出时自动 respawn 并重试（最多 2 次）

### 7.3 Session 管理

```
/data/files/{project_id}/secflow-app-firmware-unpacker/
└── {task_id}/
    ├── input/                ← 上游产物（固件路径）
    ├── output/               ← 解包产物
    │   ├── flag              ← 0/1
    │   ├── summary.md        ← 解包摘要
    │   └── reason.md         ← 解包理由
    ├── run/                  ← 中间产物
    │   ├── workspace/        ← 分析工作区
    │   ├── sessions/         ← Agent session 文件
    │   ├── round_001/        ← 每轮日志 + 产物
    │   │   ├── executor_messages.json
    │   │   ├── reviewer_messages.json
    │   │   ├── round_result.json
    │   │   ├── recursive_expand_manifest.json
    │   │   └── ...
    │   ├── skill_exec.json
    │   ├── skill_match.json
    │   └── stage5_skill_generation_context.json
    └── events/               ← 任务事件流
```

Session 文件由 `unpacker_engine_session.py` 管理，通过 `build_session_artifacts()` 为每个 Agent 角色创建独立的 session 上下文，并维护 `session_index.json` 索引。

## 8. 工具库与进化系统

### 8.1 工具仓库结构

```
/data/secflow-app-firmware-unpacker/tools/
├── active/                  ← 当前生效的工具（软链接到 store 的指定版本）
│   └── huawei_hdr_tool.py → ../store/.families/{family_id}/v3/huawei_hdr_tool.py
├── store/                   ← 版本化工具存储
│   └── .families/
│       └── {family_id}/
│           ├── manifest.json
│           ├── v1/
│           │   └── {tool}.py
│           ├── v2/
│           │   └── {tool}.py
│           └── v3/
│               └── {tool}.py
└── dispatcher/
    └── dispatcher_rules.json ← 特征 → 工具映射规则
```

### 8.2 Skill 生命周期

```
candidate skill (自动生成, skill_status=candidate)
    │
    │  promotion_success_count += 1
    │  (每次成功复用该 skill 解包)
    │
    ├── 达到 promotion_threshold（默认 5）
    │   └── 自动提升为 active skill
    │
    └── 连续失败
        └── → evolution 进化引擎干预
```

### 8.3 Evolution 进化引擎（`evolution_engine.py`）

进化引擎是手动触发的工具改良系统：

```
用户发起 evolution job
    │
    ▼
Round 1..N (max_rounds=3):
    │
    ├── Evolution Improver Agent (firmware-skill-evolver.md)
    │   └── 分析失败原因 → 生成改进版工具
    │
    ├── 用改进版工具执行原始任务（replay）
    │
    └── Review Agent 评估改进效果
        │
        ├── PASS → 新工具替换旧工具（版本号递增）
        │
        └── FAIL → 进入下一轮进化
```

进化引擎的关键数据流：
- 从原始任务的 `run/` 目录提取失败的 `reason.md` 和执行日志
- 在隔离的 workspace 中生成改进版工具
- 使用原始固件做 replay 验证
- 成功则将新工具存入 store，版本号 +1，更新 active 软链接

## 9. 任务调度系统

### 9.1 任务状态机

```
PENDING ──► ASSIGNED ──► RUNNING ──► SUCCESS
   │            │            │
   │            │            ├──► FAILED ──► RETRY_PREPARING ──► PENDING (重试)
   │            │            │
   │            │            └──► CANCELLING ──► CANCELLED
   │            │
   │            └── (超时未 heartbeat) ──► 回收至 PENDING (orphan recovery)
   │
   └── 用户取消 ──► CANCELLED

AWAITING_TAKEOVER ──► ASSIGNED (takeover 场景，由 scheduler 重新分配)
```

> `ASSIGNED` 是新引入的中间状态：scheduler 将任务显式分配给特定 dispatcher worker 后进入此状态，dispatcher 单槽空闲时自动启动执行。这替代了旧版的 `CLAIMED` 争抢模式。

### 9.2 Scheduler + Dispatcher 分离调度

旧版架构中 `dispatcher` 既负责任务分配又负责执行。新版将两者拆分为独立角色：

```
Scheduler Loop (每 polling-interval 秒):
│
├── 1. 扫描 STUCK RETRY_PREPARING 任务 → 回收
├── 2. 扫描孤儿任务 (heartbeat 超时) → 回收至 PENDING
├── 3. _scheduler_assign_tasks():
│   ├── 查询空闲 dispatcher (role=dispatcher, state=idle, active_tasks=0)
│   ├── 查询 PENDING / AWAITING_TAKEOVER / RETRY_PREPARING 任务
│   └── _assign_task_to_worker(): 任务 → ASSIGNED 状态，绑定 worker_id
│
└── 4. 处理进化任务 (evolution jobs)

Dispatcher Loop (每 polling-interval 秒):
│
├── 1. _dispatcher_start_assigned_task():
│   ├── 检查本地 active_tasks == 0 (单槽空闲)
│   ├── 查询 assigned_worker_id == self 且 status == ASSIGNED 的任务
│   └── _launch_task_runner():
│       ├── [pre-run] agent_sanitizer.cleanup(phase="pre-run")
│       │   └── 失败 → 任务重新排队 (RETRY_PREPARING)
│       ├── subprocess: python task_runner.py
│       └── [post-run] agent_sanitizer.cleanup(phase="post-run")
│
└── 2. 处理进化任务
```

**关键设计**：
- **显式分配取代争抢**：scheduler 通过 `_assign_task_to_worker()` 显式将任务绑定到特定 dispatcher，避免多 worker 同时争抢同一任务的竞态
- **assignment_generation**：每次重新分配递增，防止过期分配被错误执行
- **单槽确保隔离**：dispatcher 的 `_runtime_max_concurrent()` 固定返回 `1`，保证 Agent 进程不互相干扰

### 9.3 Agent 进程清理器 (agent_sanitizer.py)

新增模块，在任务执行前后扫描 `/proc` 文件系统，清理残留的 AI Agent 进程：

```
run_agent_cleanup(worker_id, phase, task_id)
  │
  ├── _collect_suspects(task):
  │   └── 遍历 /proc/{pid}/:
  │       • 匹配进程名包含 pi/codex/claude/opencode
  │       • 匹配 cwd 或 cmdline 包含任务相关路径
  │       • 匹配 ppid != 1 (非孤儿 init 进程)
  │
  ├── _kill_process_tree(pid):
  │   ├── SIGTERM → 等待 3s
  │   └── 仍存活 → SIGKILL
  │
  └── 结果写入 TaskCleanupScan 表
       └── 更新 WorkerInstance.last_cleanup_* 字段
```

**两阶段清理**：
| 阶段 | 时机 | 失败处理 |
|:---|:---|:---|
| `pre-run` | 任务启动前 | 任务重新排队 (RETRY_PREPARING)，不执行 |
| `post-run` | 任务结束后 | 记录残留进程数，不影响任务结果 |

### 9.4 取消机制

取消是分层级的、有宽限期的：

```
用户 POST /cancel
    │
    ▼
DB: cancel_requested_at = now()
    │
    ├── Grace Phase (cancel_grace_seconds, 默认 10s):
    │   └── 设置 cancel_grace_deadline
    │   └── 通过 cancel_check() 通知 Runner
    │   └── Runner 收到 → 优雅关闭 Agent → 正常写入结果
    │
    └── Force Phase (cancel_force_seconds, 默认 30s):
        └── SIGTERM → 等待 → SIGKILL
        └── 任务状态强制变更为 CANCELLED
```

## 10. 数据模型

### 10.1 核心表

| 表名 | 用途 |
|:---|:---|
| `unpack_tasks` | 解包任务主表，包含完整生命周期字段 |
| `task_events` | 任务事件流（SSE 事件持久化） |
| `worker_instances` | Worker 实例注册与心跳（含运行时状态 state / role / drain） |
| `task_cleanup_scans` | Agent 进程清理记录（pre-run / post-run） |
| `service_configs` | 动态配置（并发数、超时、LLM 绑定等） |
| `workspace_cleanup_jobs` | 工作目录清理任务 |
| `skill_generation_jobs` | 技能自动生成任务 |
| `evolution_jobs` | 手动进化任务 |
| `evolution_rounds` | 进化轮次记录 |

### 10.2 UnpackTask 关键字段

```
┌─────────────────────────────────────────────────────────┐
│ 基础信息:                                                │
│   id, project_id, firmware_path, output_path            │
│                                                         │
│ 父子关系 (binary-security 编排):                         │
│   task_origin_type, parent_project_id, parent_task_id   │
│   parent_task_type, parent_stage_name,                  │
│   parent_stage_item_id, parent_stage_item_key           │
│                                                         │
│ 调度状态:                                                │
│   status, owner_id, assigned_worker_id, assigned_pod_name │
│   dispatch_token, dispatch_owner_id, assignment_generation│
│   dispatch_claimed_at, dispatch_lease_expires_at          │
│   heartbeat_at, current_stage, lease_expires_at,          │
│   run_lease_expires_at, takeover_count                    │
│                                                         │
│ 取消状态:                                                │
│   cancel_requested_at, cancel_grace_deadline            │
│   cancel_force_deadline, run_token                      │
│                                                         │
│ Runner 状态 (子进程):                                    │
│   runner_pid, runner_started_at, runner_heartbeat_at    │
│                                                         │
│ 执行结果:                                                │
│   result_status, result_message, rounds, error_message  │
│                                                         │
│ 工具匹配:                                                │
│   matched_skill, matched_skill_version,                 │
│   matched_skill_score, fallback_to_llm                  │
│                                                         │
│ 技能生成:                                                │
│   generated_skill_path, generated_skill_status          │
│   skill_generation_job_id, skill_generation_status      │
│                                                         │
│ 进化关联:                                                │
│   latest_evolution_job_id, latest_evolution_status      │
│   latest_evolution_final_skill_path                     │
│                                                         │
│ LLM 绑定:                                               │
│   llm_binding_snapshot (JSON)                           │
│                                                         │
│ Agent 进程清理:                                          │
│   pre_cleanup_scan_id, post_cleanup_scan_id             │
│   last_cleanup_residual_count                           │
│                                                         │
│ 归档:                                                    │
│   archive_root, runtime_root, archive_status            │
└─────────────────────────────────────────────────────────┘
```

## 11. API 设计

| 方法 | 路径 | 用途 |
|:---|:---|:---|
| `POST` | `/api/app/firmware-unpacker/projects/{id}/tasks` | 提交解包任务 |
| `GET` | `/api/app/firmware-unpacker/projects/{id}/tasks` | 任务列表（含 project_id 过滤） |
| `GET` | `/api/app/firmware-unpacker/projects/{id}/tasks/{tid}` | 任务详情 |
| `DELETE` | `/api/app/firmware-unpacker/projects/{id}/tasks/{tid}` | 删除任务 |
| `POST` | `/api/app/firmware-unpacker/projects/{id}/tasks/{tid}/cancel` | 取消任务 |
| `POST` | `/api/app/firmware-unpacker/projects/{id}/tasks/{tid}/retry` | 重试任务 |
| `GET` | `/api/app/firmware-unpacker/projects/{id}/tasks/{tid}/result` | 任务结果 |
| `GET` | `/api/app/firmware-unpacker/projects/{id}/tasks/{tid}/events` | 任务事件流 |
| `GET` | `/api/app/firmware-unpacker/projects/{id}/tasks/{tid}/log` | 任务日志 |
| `POST` | `/api/app/firmware-unpacker/projects/{id}/evolution` | 提交进化任务 |
| `POST` | `/api/app/firmware-unpacker/evolution/{jid}/confirm` | 确认进化结果（替换工具） |
| `GET` | `/api/app/firmware-unpacker/tools` | 列出可用 Python 工具 |
| `GET` | `/api/app/firmware-unpacker/cluster` | 集群 Worker 状态 |
| `GET` | `/api/app/firmware-unpacker/health` | 健康检查 |
| `GET` | `/api/app/firmware-unpacker/metrics` | Prometheus 指标 |

兼容旧接口：`POST /unpack`、`GET /tasks`、`DELETE /tasks/{id}`

## 12. 设计原则

| # | 原则 |
|:---|:---|
| 1 | **确定性优先，AI 兜底** — 规则工具链 → Python 工具 → LLM Agent，三层级联，不浪费 AI 算力在已知格式上 |
| 2 | **知识可沉淀** — 每次成功解包自动生成 skill，经足够次数验证后自动提升为正式工具 |
| 3 | **失败可进化** — 失败的工具不是丢弃，而是进入进化引擎迭代改良 |
| 4 | **Worker + Judge 闭环** — Executor 产出、Reviewer 独立校验，不通过则重试，每轮后确定性递归展开 |
| 5 | **多角色 LLM 绑定** — 不同 Agent 角色可绑定不同的 LLM provider 和 model，粗活细活分开干 |
| 6 | **显式分配，单槽隔离** — Scheduler 显式将任务绑定到特定 dispatcher（ASSIGNED 状态），替代旧版争抢模式；dispatcher 单槽执行（max=1），杜绝 Agent 进程间干扰 |
| 7 | **取消分层宽限** — 优雅取消 → 超时强制终止，保证产物完整性 |
| 8 | **格式可扩展** — 新固件格式 = 新 Dispatcher 规则 + 新 Python 工具，架构无需修改 |
| 9 | **产物契约** — 上游（binary-security）通过 `parent_*` 字段编排，下游（system-analyse）通过 output/ 产物树消费 |
| 10 | **全量可观测** — 每阶段日志、每轮产物、每个 Agent 调用 token 统计，统一存储可回溯 |

## 13. 与 SecFlow 流水线的集成

firmware-unpacker 是 binary-security 端到端流水线的第一个阶段：

```
binary-security
    │
    ▼
firmware-unpacker (解包)
    │ 产物: output/ 文件系统树 + summary.md + reason.md
    ▼
system-analyse (模块分类 + 威胁分析)
    │
    ▼
binary-to-source → entry-analyse → dataflow-analyse → dataflow-vuln-scan
```

通过 `parent_project_id`、`parent_task_id`、`parent_stage_name`、`parent_stage_item_id` 等字段，binary-security 可精确追踪每个子任务与总任务的父子关系，支持 barrier 和 mixed_streaming 两种编排模式。
