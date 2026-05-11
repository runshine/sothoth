# SecFlow Dataflow Vulnerability Scanner

> JSON 配置驱动 · Python 插件化 · 多智能体协同 · 三级评审闭环

面向复杂任务的可编排 AI 工作流引擎。通过 JSON 配置定义智能体、工作流、角色和评审策略，通过 Python 插件实现业务逻辑。

当前首要应用场景：**基于数据流分析的漏洞挖掘**。

---

## 目录

- [漏洞挖掘快速开始](#漏洞挖掘快速开始)
- [实时 Dashboard](#实时-dashboard)
- [核心特性](#核心特性)
- [架构总览](#架构总览)
- [项目结构](#项目结构)
- [命令行选项](#命令行选项)
- [漏洞挖掘执行流程](#漏洞挖掘执行流程)
- [工作目录产物说明](#工作目录产物说明)
- [JSON 配置详解](#json-配置详解)
- [插件开发指南](#插件开发指南)
- [智能体运行时扩展](#智能体运行时扩展)
- [评审机制详解](#评审机制详解)
- [测试](#测试)
- [Docker & K8S 部署](#docker--k8s-部署)

---

## 漏洞挖掘快速开始

### 前置条件

```bash
cd secflow-app-dataflow-vuln-scanner
pip install -r requirements.txt
# 确保 pi CLI 已安装（用于调用 AI 智能体）
pi --version
```

### 输入

| 输入 | 说明 |
|------|------|
| 数据流分析文件 (.md) | 外部函数的调用流追踪和数据流分析结果 |
| 源码目录 | 包含 .c / .h / .asm 文件的目录 |

### 一键运行

```bash
python3 run_vuln_scan.py \
  --data-flow /path/to/data_flow_analysis.md \
  --source-dir /path/to/source_code/
```

### 更多选项

```bash
python3 run_vuln_scan.py \
  --data-flow /path/to/data_flow.md \
  --source-dir /path/to/source/ \
  --run-name my_scan \                   # 运行名称（默认自动生成）
  --model litellm/zai-org/GLM-5 \       # AI 模型，使用 provider/model 格式
  --max-cycles 5 \                       # 评审循环次数（默认 10）
  --result-review-concurrency 3 \        # 结果评审并发上限（默认 3）
  --clean                                # 执行后清理工作目录
```

### Windows / Git Bash 运行说明

项目已兼容 Windows Git Bash：

- npm/Node 安装的 `pi.cmd`、`claude.cmd`、`codex.cmd`、`opencode.cmd` 会自动通过 Windows shell 启动。
- CLI 参数和 JSON 配置中的 Git Bash 路径（如 `/c/Users/me/data.md`）会自动转换为 Windows 路径。
- 文本文件统一按 UTF-8 读写，避免中文 Prompt/报告在 Windows 默认编码下乱码。
- Windows 下自动使用较短的 `runs/{run_name}/ws/` 工作目录和短执行 ID，降低 260 字符路径长度风险。

建议：

```bash
python --version
pi --version
python run_vuln_scan.py \
  --data-flow /c/path/to/data_flow.md \
  --source-dir /c/path/to/source
```

如果仍遇到 `File name too long` / `路径过长`，请把仓库放到较短路径（如 `C:/vulnerability_scan`），或在 Windows 中开启 Long Paths 支持。

### 使用自定义配置

如需精细控制模型、超时、插件、Prompt 等参数，可复制默认配置模板后修改：

```bash
# 1. 复制默认配置
cp config.vuln_scan_default.json my_config.json

# 2. 编辑 my_config.json，修改你关心的字段（模型/超时/评审轮次 等）
#    执行路径类字段 (workspace_root, task_file 等) 无需修改，启动器会自动覆盖

# 3. 指定配置运行 (此时 --model/--max-cycles 等 CLI 参数将被忽略)
python3 run_vuln_scan.py \
  --data-flow /path/to/data_flow.md \
  --source-dir /path/to/source/ \
  -c my_config.json
```

配置模板中可自定义的关键字段：

| 字段 | 位置 | 说明 |
|------|------|------|
| `model` | `agents[*].runtime_config.model` | AI 模型名称，必须使用 `provider/model` 格式 |
| `transport` | `agents[*].runtime_config.transport` | Pi 调用模式，默认模板使用 `rpc`（支持 pi 内建 auto-retry）；兼容 `json` |
| `api_max_retries` / `api_retry_delay` | `agents[*].runtime_config` | 框架侧 API/网络/限流错误重试次数/初始退避秒数；默认 RPC 模板为 `0`，仅在显式配置正整数时才做额外框架重试 |
| `pi_max_retries` / `pi_retry_delay` | `agents[*].runtime_config` | 框架侧 Pi 进程崩溃/中断类错误重试次数/初始退避秒数；默认 RPC 模板为 `0`，避免与长连接 RPC 会话重复重放 |
| `timeout_retry_interval_seconds` | `agents[*].runtime_config` | RPC 下 Pi/provider 原生 timeout 的固定重发间隔秒数，默认 30；可显式设为 0；不再使用 `no_progress_timeout_seconds` / `max_wall_seconds` / `max_retry_wall_seconds` 截断 prompt |
| `worker_timeout` / `advisor_timeout` | `config_payload` | 兼容旧 Profile 字段；默认 RPC 模式下不控制 prompt 超时，建议不要作为运行时超时开关使用 |
| `execution_timeout_seconds` | Profile 定义 | 服务托管的 `run_vuln_scan.py` 子进程最大执行时长；默认 `0`（不限制/禁用框架超时）；仅显式设置正整数时才会由服务请求停止并标记失败 |
| `reset_worker_session_per_cycle` | `workflows.atomic[*].engine` | Worker 是否每轮重建会话；默认 `false`，所有轮次复用同一 RPC session / pi 进程 |
| `thinking` | `agents[*].runtime_config.sdk_specific.thinking` | 思考深度，可设为 `off` / `low` / `medium` / `high` / `xhigh` |
| `max_review_cycles` | `global` 或 `workflows.atomic[*].engine` | 评审循环次数 |
| `parallel_result_review` | `global.parallel_result_review` | 是否开启结果评审并行 |
| `parallel_result_review_limit` | `global.parallel_result_review_limit` | 结果评审并发上限（默认 3） |
| `system_prompt_file` 等 | `workflows.atomic[*].roles.worker.prompts` | 自定义 Prompt 文件 |
| `plugins` / `end_plugins` | 各处 | 插件链配置 |

> 说明：当 `transport=rpc` 时，加载配置后会自动清理旧的 `no_progress_timeout_seconds` / `max_wall_seconds` / `max_retry_wall_seconds` 以及 reflection 对应 watchdog 字段，避免误以为框架仍会主动截断 Pi prompt。

### 输出

运行结束后，最终产出位于 `runs/{run_name}/workspace/.../final_output/`（Windows 下默认为 `runs/{run_name}/ws/.../final_output/`）：

```
final_output/
├── summary.md              # 综合工作报告 + 漏洞汇总
├── results/                # 漏洞详细报告
│   ├── result_001.md
│   ├── result_002.md
│   └── ...
└── index.json              # 产出索引
```

同时 `runs/{run_name}/run.log` 保存了完整的运行日志。

---

## 实时 Dashboard

可启动前端可观测性 Dashboard，实时查看 `runs/` 下所有运行记录、分数趋势、评审问题、评审 JSON、结果报告、会话 Prompt/Response 和日志：

```bash
python3 run_dashboard.py --port 8501
# 打开 http://localhost:8501
```

更多说明见 [`dashboard/README.md`](dashboard/README.md)。

---

## 核心特性

| 特性 | 说明 |
|------|------|
| **JSON 配置驱动** | 智能体、工作流、角色、评审策略全部在 JSON 文件中定义 |
| **4 种 Agent 适配** | Claude Code / Codex / OpenCode / Pi Agent |
| **Pi JSON 运行模式** | Pi Agent 使用 `pi --mode json --model provider/model -p`，解析 JSON Lines 输出并支持 API/pi 进程双层重试 |
| **原子 + 组合工作流** | 原子工作流不可拆分，组合工作流按阶段串联 |
| **三级质量保障** | 自我反思 → 全局评审 → 结果评审（逐项误报检测） |
| **评审循环闭环** | 不通过→回 Worker 修改→再评审，最多 N 轮 |
| **6 种插件返回码** | 控制流可继续/跳过/重启/退出 |
| **完整持久化记录** | 评审记录、状态变更、Agent 会话全部落盘 |
| **实时可观测 Dashboard** | 聚合查看 runs、轮次分数、评审问题、评审 JSON、会话 Prompt/Response、日志 |
| **全量日志捕获** | stdout + stderr 同时写入日志文件，去除 ANSI 色彩 |

---

## 架构总览

```
┌───────────────────────────────────────────────────────────┐
│                   入口层 (main.py / run_vuln_scan.py)      │
│         加载 JSON → 初始化注册表 → 启动组合工作流引擎       │
├───────────────────────────────────────────────────────────┤
│                      编排层 (engine/)                      │
│   CompositeWorkflowEngine   ←→   AtomicWorkflowEngine     │
│   阶段调度 · 任务扇出             Worker · 评审 · 循环     │
├───────────────────────────────────────────────────────────┤
│                  智能体运行时层 (agents/)                   │
│   ClaudeCode │ Codex │ OpenCode │ PiAgent                 │
├──────────┬──────────┬──────────┬──────────────────────────┤
│ plugins/ │ review/  │workspace/│ recorder/                │
│ 6种返回码 │全局+结果  │目录嵌套   │ 持久化记录               │
└──────────┴──────────┴──────────┴──────────────────────────┘
```

---

## 项目结构

```
workflow-framework/
│
├── run_vuln_scan.py                  # ★ 漏洞挖掘一键启动器
│
├── config/
│   └── vuln_scan_default.json        # ★ 默认配置模板 (复制后用 -c 指定)
│
├── src/                              # ══ 框架核心代码 ══
│   ├── main.py                       # 框架通用入口 (支持 --log-file)
│   │
│   ├── config/                       # 配置系统
│   │   ├── models.py                 # Pydantic 模型 (JSON 结构定义)
│   │   └── loader.py                 # 加载 + 校验 + 引用完整性检查
│   │
│   ├── engine/                       # 工作流引擎
│   │   ├── models.py                 # 状态机 + TaskItem + 上下文
│   │   ├── worker.py                 # Worker 执行 + 反思 + 总结
│   │   ├── atomic.py                 # 原子工作流引擎 (完整闭环)
│   │   └── composite.py              # 组合工作流引擎 (多阶段)
│   │
│   ├── agents/                       # 智能体运行时层
│   │   ├── base.py                   # 抽象基类
│   │   ├── models.py                 # AgentMessage / AgentResponse
│   │   ├── registry.py               # 注册表
│   │   └── runtimes/                 # 4 种 SDK 适配器
│   │       ├── claude_code.py
│   │       ├── codex.py
│   │       ├── opencode.py
│   │       └── pi_agent.py
│   │
│   ├── review/                       # 评审子系统
│   │   ├── models.py                 # 评审结果解析 (JSON/Markdown/关键词)
│   │   ├── global_review.py          # 全局评审 (串行)
│   │   ├── result_review.py          # 结果评审 (并行+串行)
│   │   ├── scheduler.py              # 统一调度
│   │   └── state.py                  # 跨 cycle 状态追踪
│   │
│   ├── plugins/                      # 插件系统
│   │   ├── base.py                   # BasePlugin + 6 种返回码
│   │   ├── registry.py               # 动态加载
│   │   ├── executor.py               # 串行执行 + 分支
│   │   └── builtin/                  # 6 个内置插件
│   │       ├── env_setup.py          #   环境变量设置
│   │       ├── workspace_init.py     #   工作目录初始化
│   │       ├── task_validator.py     #   输入任务校验
│   │       ├── result_archiver.py    #   结果归档 (tar.gz)
│   │       ├── final_output_collector.py  # ★ 最终产出收集
│   │       └── next_task_generator.py#   下阶段任务生成
│   │
│   ├── recorder/recorder.py          # 持久化记录
│   ├── workspace/manager.py          # 目录管理
│   └── utils/
│       ├── logger.py                 # structlog + TeeStream 日志
│       ├── visual_log.py             # 彩色阶段标记
│       ├── file_ops.py               # 文件读写
│       └── template.py               # Jinja2 模板渲染
│
├── prompts/                          # Prompt 模板
│   ├── vuln_scan/                    # ★ 漏洞挖掘专用 prompts
│   │   ├── worker_system.md          #   Worker 人设
│   │   ├── worker_user.md            #   初始挖掘指令模板
│   │   ├── worker_rework.md          #   返工/closure 指令模板
│   │   ├── reflect_completeness.md   #   自我反思
│   │   ├── summary.md                #   总结输出格式
│   │   ├── global_review_completeness_sys.md  # 全面性评审标准
│   │   ├── global_review_completeness_user.md # 全面性评审提问
│   │   ├── global_review_depth_sys.md         # 深入性评审标准
│   │   ├── global_review_depth_user.md        # 深入性评审提问
│   │   ├── result_review_sys.md      #   结果评审标准
│   │   └── result_review_user.md     #   结果评审提问
│   └── *.md                          # 通用/旧版 prompts
│
├── runs/                             # 运行实例 (自动生成)
│   └── vuln_scan/                    # 示例配置
│       ├── config.json
│       └── input/task.md
│
├── tests/
│   ├── mocks/mock_agent_runtime.py
│   ├── integration/test_full_atomic_workflow.py
│   └── unit/test_review_models.py
│
├── Dockerfile
├── k8s/job.yaml
└── pyproject.toml
```

---

## 命令行选项

### `run_vuln_scan.py` — 漏洞挖掘启动器

```
python3 run_vuln_scan.py --data-flow <path> --source-dir <path> [选项]
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--data-flow, -d` | *(必须)* | 数据流分析文件 (.md) |
| `--source-dir, -s` | *(必须)* | 源码目录 |
| `--config, -c` | | 自定义配置文件 (复制 `config.vuln_scan_default.json` 后修改) |
| `--run-name, -n` | 自动生成 | 运行名称 |
| `--model, -m` | `icsl/zai-org/GLM-5` | AI 模型，使用 `provider/model` 格式 (未指定 `-c` 时生效) |
| `--thinking` | `high` | 思考深度 (可选: `off` / `low` / `medium` / `high` / `xhigh`，未指定 `-c` 时生效) |
| `--max-cycles` | `10` | 最大评审循环次数 (未指定 `-c` 时生效) |
| `--result-review-concurrency` | `3` | 结果评审并发上限 (未指定 `-c` 时生效) |
| `--clean` | | 执行后删除工作目录 |

启动器自动完成：生成 task.md → 生成 config.json → 启用日志文件 → 调用框架 → 展示结果路径。

### `python -m src.main` — 框架通用入口

```
python -m src.main --config <path> [--keep-workspace | --clean-workspace] [--log-file <path>]
```

| 选项 | 默认 | 说明 |
|------|------|------|
| `--config, -c` | *(必须)* | JSON 配置文件路径 |
| `--keep-workspace` | ✅ 默认 | 保留工作目录 |
| `--clean-workspace` | | 执行后删除工作目录 |
| `--log-file` | | 同时将所有终端输出记录到日志文件 |

---

## 漏洞挖掘执行流程

```
输入                              执行流程                                  输出
┌──────────────┐                                                    ┌───────────────┐
│ 数据流分析.md │    ① 启动插件 (env_setup → workspace_init)         │ final_output/ │
│ 源码目录/     │    ② Worker 分析 (读DFA + 读源码 → 找漏洞)         │  summary.md   │
└──────┬───────┘    ③ 自我反思 (覆盖度/深度/质量自检)                │  results/     │
       │            ④ 总结 (写 summary.md + results/*.md)           │   result_*.md │
       ▼            ⑤ 全局评审 (整体质量检查)                       └───────────────┘
  run_vuln_scan.py  ⑥ 结果评审 (逐个漏洞误报检测)                   ┌───────────────┐
                    ⑦ 不通过? → 注入反馈回②, 最多 N 轮              │ run.log       │
                    ⑧ 结束插件 (归档 → 收集 → 生成下阶段任务)        └───────────────┘
```

### Worker 每轮做什么

1. **读取数据流分析**：理解目标函数的输入、污点传播路径、终点类型
2. **读取源代码**：沿 EXPORT 终点跟入函数实现，沿 USED 终点检查操作安全性
3. **检测漏洞模式**：缓冲区溢出、整数溢出、返回值忽略、类型混淆、越界访问等
4. **撰写报告**：每个漏洞一个 `result_NNN.md`，要求完整证据链

### 评审员做什么

| 角色 | 评审对象 | 判定标准 |
|------|---------|---------|
| 全局评审 | summary + 所有结果 | 数据流覆盖度、源码分析深度、报告完整性 |
| 结果评审 | 每个 result_NNN.md | 代码证据、数据流路径、触发条件、影响评估 |

评审员会尝试**证伪**每个漏洞报告。只有经过证伪仍成立的发现才能通过。

---

## 工作目录产物说明

运行后在 `runs/{run_name}/` 下生成以下结构：

### 顶层 run 目录

```
runs/{run_name}/
├── config.json                     # 本次运行的完整配置
├── input/task.md                   # 自动生成的任务描述
├── output/execution_summary.json   # 执行总结（成功/失败/耗时）
├── run.log                         # ★ 完整运行日志（终端所有内容）
└── workspace/                      # 工作空间根目录
    └── pipeline_{run_name}_run_001/
        └── stage_01_vuln_scan/
            └── vuln_scan_initial_001/   # ← 原子工作流执行现场
```

### 原子工作流执行目录 (`vuln_scan_initial_001/`)

```
vuln_scan_initial_001/
│
│  ════ 最终结论 (给人看的) ════
│
├── final_output/                   ★ 干净的最终产出目录
│   ├── summary.md                     综合工作报告 + 漏洞汇总
│   ├── results/                       漏洞详细报告
│   │   ├── result_001.md
│   │   ├── result_002.md
│   │   └── ...
│   └── index.json                     产出文件索引
│
│  ════ 框架元数据 (机器用) ════
│
├── _meta/
│   ├── state.json                     当前状态快照 (completed/failed)
│   ├── workflow_result.json           执行结果 (状态/轮次/错误)
│   ├── reflections/                   Worker 自我反思记录
│   │   └── reflect_001_*.json            每轮反思的问答
│   ├── review_summaries/              每轮评审结果概要 ★ 排查首选
│   │   ├── cycle_001.json                第1轮: 全局是否通过/哪些结果失败
│   │   ├── cycle_002.json                第2轮
│   │   └── cycle_003.json                第3轮
│   └── summary_snapshots/             summary.md 各轮快照
│       ├── cycle_001_after_summary.md    第1轮 Worker 写完的版本
│       ├── cycle_002_after_summary.md    第2轮修改后版本
│       ├── cycle_003_after_summary.md    第3轮修改后版本
│       └── ...
│
│  ════ 输入 / 工作区 / 产出 ════
│
├── input/task.md                   输入任务快照 (复制件, 保证可复现)
├── working/                        Worker 中间工作区 (预留)
├── summary.md                      综合报告 (Worker 直接写的, = final_output 中的源)
├── results/                        漏洞报告 (评审循环中会被修改/删除/重编号)
│   ├── result_001.md
│   └── ...
├── results_archive.tar.gz          results/ 的归档包
│
│  ════ 正式评审记录 ════
│
├── reviews/
│   ├── global/                     全局评审
│   │   ├── cycle_001/
│   │   │   └── global_quality.json    第1轮全局评审员的评审结果
│   │   ├── cycle_002/
│   │   │   └── global_quality.json
│   │   └── cycle_003/
│   │       └── global_quality.json
│   └── results/                    结果评审 (按漏洞报告建桶)
│       ├── result_001/
│       │   └── cycle_003/
│       │       └── result_fp_check.json   误报检测员的评审结果
│       ├── result_002/
│       │   └── cycle_002/
│       │       └── result_fp_check.json
│       └── ...
│
│  ════ 下阶段传递 ════
│
├── output/                         下阶段任务 (组合工作流间传递用)
│   ├── next_tasks.json                任务索引
│   └── task_result_*.md               每个结果的下游副本
│
│  ════ 调试现场 ════
│
├── sessions/                       Agent 会话日志 + 统一调用 trace
│   ├── {session_id}/                  每个 session 一个子目录（如 pi_*/cc_*/codex_*/oc_*）
│   │   ├── *.jsonl                       运行时原生会话记录（仅部分 runtime 如 pi 提供）
│   │   └── calls/                       统一的每次 send_message / execute 落盘现场
│   │       └── 001_xxxxxxxx/
│   │           ├── command.txt             实际执行的完整命令行
│   │           ├── request.json            调用元数据 (runtime/mode/model/tools/路径/turn/retry)
│   │           ├── system_prompt.md        本次发送的 system prompt（若有）
│   │           ├── user_prompt.md          本次发送的 user prompt
│   │           ├── effective_prompt.md     实际传给 CLI 的合成 prompt（部分 runtime 如 codex/opencode）
│   │           ├── stdout.txt              CLI 标准输出
│   │           ├── stderr.txt              CLI 标准错误
│   │           ├── response.txt            框架收到/解析后的响应文本
│   │           └── response.json           return_code / duration / error 等结果
│   └── ...
│
└── plugins/                        插件执行记录 (预留)
    ├── start/
    └── end/
```

### 关键文件速查

| 我要... | 看这个文件 |
|---------|-----------|
| 看最终漏洞清单 | `final_output/summary.md` + `final_output/results/` |
| 看每轮评审通过/失败 | `_meta/review_summaries/cycle_NNN.json` |
| 看执行是否成功 | `_meta/workflow_result.json` |
| 看某个漏洞为什么被驳回 | `reviews/results/result_NNN/cycle_NNN/result_fp_check.json` |
| 看全局评审意见 | `reviews/global/cycle_NNN/global_quality.json` |
| 看 Worker 怎么修改报告 | `_meta/summary_snapshots/cycle_NNN_after_summary.md`（对比不同轮次） |
| 看 Agent 原始对话 | `sessions/*/...jsonl`（若该 runtime 提供原生日志） |
| 看某次调用的完整命令行与 prompt | `sessions/*/calls/*/command.txt` + `user_prompt.md` + `system_prompt.md` |
| 看完整运行日志 | `runs/{run_name}/run.log` |

### reviews/ 目录说明

评审记录**按"当时的文件名"建桶**，不是稳定 ID。如果 Worker 在某轮删除了 `result_004.md`，`reviews/results/result_004/` 仍然保留（历史不删除），但 `results/` 目录里已无此文件。

每个评审记录 JSON 包含：
- `passed`：是否通过
- `verdict`：框架归一化后的稳定判定标签（如 `PASS` / `REJECT` / `FALSE_POSITIVE` / `INSUFFICIENT_INFO`）
- `feedback`：稳定的简明反馈摘要（用于日志/UI 展示，不再直接写入整段原文）
- `feedback_detail`：详细评审理由（优先取结构化字段；供 Worker 二轮修正使用）
- `raw_response`：评审员原始响应（未经解析、原样保存）
- `scores`：各维度评分
- `confidence`：置信度

---

## JSON 配置详解

完整 JSON 配置包含 5 个顶层节段：

```jsonc
{
  "version": "1.0",
  "global": { ... },           // 全局: workspace_root, log_level, max_review_cycles
  "agents": [ ... ],           // 智能体: id, type, model, transport, tools
  "plugins": [ ... ],          // 插件: module_path, class_name, config
  "workflows": {
    "atomic": [ ... ],         // 原子工作流: roles(worker+advisors), prompts, plugins
    "composite": [ ... ]       // 组合工作流: stages 串联
  },
  "execution": { ... }         // 入口: entry_workflow, input_task, output_dir
}
```

> 使用 `run_vuln_scan.py` 时无需手写配置，启动器自动生成。

### 配置加载时自动校验

1. JSON 语法 → 2. Pydantic 类型 → 3. agent_id/plugin_id 引用完整性 → 4. workflow_ref 存在且类型匹配 → 5. 组合工作流无循环引用 → 6. stage sequence 递增

---

## 插件开发指南

### 实现接口

```python
from src.plugins.base import BasePlugin, PluginContext, PluginResult, PluginResultCode

class MyPlugin(BasePlugin):
    @property
    def plugin_id(self) -> str:
        return "my_plugin"

    async def execute(self, ctx: PluginContext) -> PluginResult:
        # ctx.working_dir / ctx.task_file / ctx.plugin_config
        # ctx.summary_file / ctx.results_dir (仅结束阶段)
        return PluginResult(code=PluginResultCode.OK_NEXT, message="OK")
```

### 6 种返回码

| 返回码 | 后续行为 |
|--------|---------|
| `OK_NEXT` | 继续下一插件 |
| `OK_END_STAGE` | 跳过后续插件 |
| `ERROR_CONTINUE` | 记录错误，继续 |
| `ERROR_END_NEXT` | 结束当前阶段 |
| `ERROR_RESTART` | 重试整个工作流 |
| `ERROR_EXIT` | 立即终止 |

### 内置插件

| ID | 阶段 | 功能 |
|----|------|------|
| `env_setup` | start | 设置环境变量 |
| `workspace_init` | start | 创建标准子目录 |
| `task_validator` | start | 校验输入任务文件 |
| `result_archiver` | end | 归档 results/ 为 tar.gz |
| `final_output_collector` | end | 收集 summary + results 到 final_output/ |
| `next_task_generator` | end | 生成下阶段任务清单 |

---

## 智能体运行时扩展

继承 `BaseAgentRuntime` 并实现 5 个方法：

```python
class MyRuntime(BaseAgentRuntime):
    async def initialize(self) -> None: ...
    async def create_session(self) -> str: ...
    async def send_message(self, message, system_prompt=None,
                           session_id=None, working_dir=None) -> AgentResponse: ...
    async def multi_turn_execute(self, system_prompt, user_prompt,
                                  working_dir, max_turns=30,
                                  session_id=None) -> AgentResponse: ...
    async def close_session(self, session_id) -> None: ...
    async def shutdown(self) -> None: ...
```

注册后在 JSON 中通过 `"type": "my_runtime"` 使用。

---

## 评审机制详解

### 全局评审

- **评审对象**：任务 + summary + 结果清单
- **执行方式**：多个参谋 **串行**，任一不通过 → 整体回退
- **默认**：`re_review_on_cycle: true`（每轮都重审）

### 结果评审

- **评审对象**：`results/` 下每个 `.md` 文件
- **执行方式**：结果间并行（默认模板已开启，默认并发上限 3，可配置）× 结果内串行
- **默认**：`re_review_on_cycle: false`（已通过不重审）

### 评审响应解析

框架自动解析以下格式：

```json
{"passed": true, "feedback": "...", "scores": {...}, "confidence": 0.9}
```

并统一归一化为稳定字段：

```json
{
  "passed": true,
  "verdict": "PASS",
  "feedback": "PASS（通过） - 简明摘要",
  "feedback_detail": "详细评审理由",
  "raw_response": "评审员原始输出"
}
```

也支持：
- 嵌套 JSON（`verdict` / `overall_verdict` / `recommendation` 等字段）
- Markdown 中的 `评审结论: **FALSE_POSITIVE**` 格式
- 关键词检测（`通过` / `reject` / `误报` 等）
- `confidence: "HIGH"` 等字符串枚举自动转数值

---

## 测试

```bash
# 集成测试（Mock Agent，验证引擎流程）
python -m tests.integration.test_full_atomic_workflow --keep --dump-all

# 单元测试（评审解析器）
python -m pytest tests/unit/test_review_models.py -v
```

---

## Docker & K8S 部署

### Docker 镜像说明

仓库根目录已经提供可直接构建的 `Dockerfile`，镜像默认启动 REST 微服务，同时保留 `vuln-scan` 与 `framework-run` 命令用于单次 CLI 扫描和底层框架调试。

镜像内默认包含：
- Python 运行环境与项目依赖
- `run_vuln_scan.py`
- 框架核心代码、prompts、默认配置模板
- `pi` CLI（默认构建时安装，可通过 build arg 关闭）

### 1. 构建镜像

```bash
docker build -t secflow-app-dataflow-vuln-scanner .
```

### 1.1 LLM Provider 配置来源

服务启动时会调用 `sync_providers_to_pi()`，从平台配置中心读取已启用的 LLM Provider，并生成 `/root/.pi/agent/models.json`。如果 `local_pi` Provider 启用了名为 `models.json` 的配置文件注入，则该注入文件会作为最终 Pi 配置原样写入 `/root/.pi/agent/models.json`；否则才按 Provider 表单字段生成。K8S 部署不再通过 Secret 或镜像构建注入本机 `~/.pi` / `~/.copilot`。

可选构建参数：

```bash
# 如需关闭 pi CLI 安装（仅做纯框架/调试镜像）
docker build \
  --build-arg INSTALL_PI_CLI=0 \
  -t secflow-app-dataflow-vuln-scanner .
```

### 2. 准备宿主机输入目录

建议在宿主机准备如下目录：

```text
docker/input/
├── data_flow.md      # 数据流分析 markdown 文件
└── source/           # 源码目录（.c/.h/.asm 等）
```

### 3. 直接运行漏洞扫描

```bash
docker run --rm \
  -v "$(pwd)/docker/input:/data:ro" \
  -v "$(pwd)/runs:/app/runs" \
  -v "$HOME/.pi:/root/.pi" \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  secflow-app-dataflow-vuln-scanner \
  vuln-scan \
  --data-flow /data/data_flow.md \
  --source-dir /data/source \
  --run-name demo_scan \
  --model icsl/zai-org/GLM-5 \
  --max-cycles 6
```

说明：
- `docker/input` 挂到容器内 `/data`
- `runs` 挂到容器内 `/app/runs`，用于持久化运行结果
- `$HOME/.pi:/root/.pi` 用于复用宿主机已有的 `pi` CLI 登录态/配置
- 若你使用 API Key 方式接入 provider，也可以只传环境变量，不挂载 `/root/.pi`

### 4. 继续已有 run

```bash
docker run --rm \
  -v "$(pwd)/runs:/app/runs" \
  -v "$HOME/.pi:/root/.pi" \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  secflow-app-dataflow-vuln-scanner \
  vuln-scan \
  --resume-run-dir runs/demo_scan \
  --extra-cycles 5
```

### 5. 使用自定义配置运行通用框架

如果你想直接运行底层框架 JSON 配置，请使用内置分发命令 `framework-run`：

```bash
docker run --rm \
  -v "$(pwd)/my-config:/config:ro" \
  -v "$(pwd)/workspace:/workspace" \
  -v "$HOME/.pi:/root/.pi" \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  secflow-app-dataflow-vuln-scanner \
  framework-run \
  --config /config/workflow.json \
  --keep-workspace
```

### 6. 启动 REST 微服务

镜像默认启动 REST 微服务，API 前缀为 `/api/dataflow-vuln-scanner`。服务启动后会初始化数据库、注册调度 Worker，并通过后台调度循环执行前端下发的任务。

```bash
docker run --rm -p 8080:8080 \
  -v "$(pwd)/config.yaml:/app/config.yaml:ro" \
  -v "$(pwd)/docker/data:/data" \
  -v "$HOME/.pi:/root/.pi" \
  secflow-app-dataflow-vuln-scanner:latest
```

常用健康检查：

```bash
curl http://127.0.0.1:8080/api/dataflow-vuln-scanner/health
curl http://127.0.0.1:8080/api/dataflow-vuln-scanner/ready
```

典型任务下发流程：

```bash
# 1. 创建项目默认 Profile
curl -X POST http://127.0.0.1:8080/api/dataflow-vuln-scanner/profiles \
  -H 'Content-Type: application/json' \
  -d '{
    "project_id": "default",
    "name": "默认数据流漏洞挖掘模板",
    "template_kind": "vuln_scan_default",
    "config_payload": {
      "model": "icsl/zai-org/GLM-5",
      "thinking": "high",
      "max_review_cycles": 6,
      "timeout_max_retries": 3,
      "timeout_retry_interval_seconds": 30,
      "result_review_concurrency": 3,
      "runtime_overrides": {}
    },
    "is_default": true,
    "enabled": true,
    "default_priority": 100,
    "max_retry_count": 0,
    "execution_timeout_seconds": 0
  }'

# 2. 下发扫描任务
curl -X POST http://127.0.0.1:8080/api/dataflow-vuln-scanner/tasks \
  -H 'Content-Type: application/json' \
  -d '{
    "project_id": "default",
    "title": "demo package scan",
    "task_markdown": "# Package List\n\n- demo.tar.gz\n",
    "artifact_refs": [],
    "priority": 100,
    "runtime_overrides": {}
  }'

# 3. 查询 Run 和执行详情
curl 'http://127.0.0.1:8080/api/dataflow-vuln-scanner/tasks?project_id=default'
curl 'http://127.0.0.1:8080/api/dataflow-vuln-scanner/runs?project_id=default'
curl 'http://127.0.0.1:8080/api/dataflow-vuln-scanner/runs/by-task?project_id=default&task_id=<task_id>'
curl 'http://127.0.0.1:8080/api/dataflow-vuln-scanner/runs/<run_id>'
curl 'http://127.0.0.1:8080/api/dataflow-vuln-scanner/runs/<run_id>/files'
```

### 7. 使用 `docker compose`

仓库根目录已提供 `docker-compose.yml` 和 `.env.example`：

```bash
cp .env.example .env
# 按需修改 .env 中的 SERVICE_PORT / HOST_PI_HOME / HOST_DATA_DIR 等

docker compose build
docker compose up dataflow-vuln-scanner
```

默认微服务 compose 约定：
- 服务端口：`8080`
- 配置文件：`./config.yaml`
- 共享数据目录：`./docker/data`
- 运行结果目录：`./runs`

如果仍需单次 CLI 扫描，可以使用 `cli` profile：

```bash
docker compose --profile cli run --rm vuln-scan
```

CLI 模式约定：
- 宿主机输入目录：`./docker/input`
- 宿主机结果目录：`./runs`
- 宿主机 `pi` 配置目录：`.env` 中的 `HOST_PI_HOME`

### 8. 容器内可用入口

```bash
# CLI 漏洞扫描入口
docker run --rm secflow-app-dataflow-vuln-scanner:latest vuln-scan --help

# 底层框架 JSON 运行
docker run --rm secflow-app-dataflow-vuln-scanner:latest framework-run --help

# 服务模式，镜像默认即为 serve
docker run --rm -p 8080:8080 secflow-app-dataflow-vuln-scanner:latest
docker run --rm secflow-app-dataflow-vuln-scanner:latest serve

# 进入 shell 调试
docker run --rm -it --entrypoint bash secflow-app-dataflow-vuln-scanner:latest
```

### 9. K8S

K8S 模式下，`/root/.pi/agent/models.json` 只由服务启动时的 `sync_providers_to_pi()` 生成；数据来自平台配置中心的 LLM Provider。`local_pi` 的 `models.json` 配置文件注入是最高优先级来源，内容必须是合法 JSON。不要再创建或挂载运行时 Agent home Secret。

服务数据库密码与服务间 machine token 不再写入 ConfigMap，部署前需要先创建 Secret：

```bash
kubectl -n secflow-ns create secret generic secflow-app-dataflow-vuln-scanner-secret \
  --from-literal=db-password='<mysql-password>' \
  --from-literal=service-machine-token='<machine-token>'
```

如需修改可用模型、Provider、API Base、API Key、context window 或 max tokens，请在平台配置中心的 LLM Provider 中修改；Pod 重启或任务启动前的同步会写入新的 `models.json`。

当前平台集成清单可参考：

- `13-secflow-service/00-secflow-107-00-app-dataflow-vuln-scanner-configmap.yaml`
- `13-secflow-service/00-secflow-107-01-app-dataflow-vuln-scanner-deployment.yaml`
- `13-secflow-service/00-secflow-107-02-app-dataflow-vuln-scanner-service.yaml`
- `13-secflow-service/image_build/secflow-app-dataflow-vuln-scanner/k8s-deployment.yaml`

历史清单文件也可能仍保留在 `00-secflow-103-*`：

- `00-secflow-103-00-app-dataflow-vuln-scanner-configmap.yaml`
- `00-secflow-103-01-app-dataflow-vuln-scanner-deployment.yaml`
- `00-secflow-103-02-app-dataflow-vuln-scanner-service.yaml`

平台 Ingress 需要包含 `/api/dataflow-vuln-scanner` 路由，前端页面会直接通过这个前缀读取任务、事件、产物、Profile、Worker 与有效配置。

---

## License

Internal use only.
