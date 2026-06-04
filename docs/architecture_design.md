# SecFlow 架构设计

## 1. 定位

SecFlow（Sothoth v2）是一套基于 Kubernetes 的自动化安全测试平台。它以固件/二进制/源码为输入，经多阶段流水线——解包、模块分类、二进制溯源、入口分析、数据流追踪、漏洞挖掘——产出结构化的安全认知，覆盖从"拿到一个固件"到"定位高危漏洞"的完整链路。

平台不绑定单一分析手段：每条流水线阶段由独立微服务承载，支持 AI Agent（pi）驱动的语义审查与规则式工具链的组合编排，可按需裁剪、替换或扩展。

## 2. 挑战

安全分析面临两个核心瓶颈：

**分析深度的矛盾。** 固件分析需要穿透多级封装——从固件镜像到文件系统、从二进制到源码、从模块到函数、从入口到数据流——每一步都会引入噪音和误差。传统工具链只能在局部完成片段分析，跨阶段信息无法传递、继承或修正。

**人工与自动化的断裂。** 安全工程师的工作模式是"跑工具 → 读报告 → 人工追踪 → 写结论"，分析吞吐量被人的精力锁死。当分析对象是百万行级别的固件代码时，这条链路会在第一个步骤崩溃——不是工具跑不完，而是结果太多、人看不过来。

SecFlow 的解法不是"用 AI 替代人工做同样的工作"，而是重新定义分析形态：将固件分析拆解为可独立校验、可级联传导的阶段流水线，每一阶段由 AI Agent 和确定性工具联合执行，阶段之间通过结构化产物契约传递上下文。

## 3. 核心能力

系统回答五个问题：

| | 问题 | 方式 |
|:---|:---|:---|
| ① | 固件里有什么？ | 解包引擎 → 提取文件系统，识别二进制/脚本/配置/内核模块 |
| ② | 各模块的外部入口在哪？ | entry-analyse → Worker+Judge 流水线定位外部输入入口函数 |
| ③ | 外部输入如何传播？ | dataflow-analyse → 递归追踪污点调用链，BFS 展开子调用 |
| ④ | 传播路径上存在漏洞吗？ | dataflow-vuln-scan → 多维语义验证，四维校验矩阵 |
| ⑤ | 哪些漏洞危害最大？ | weakness 聚合 → 全局排序，综合严重度和可利用性 |

## 4. 系统全景

```
                           ┌──────────────────┐
                           │   secflow.ai      │  (NGINX Ingress)
                           └────────┬─────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────────┐
          │                         │                             │
    ┌─────▼─────┐           ┌──────▼──────┐             ┌────────▼────────┐
    │ Platform  │           │  Analysis   │             │  Agent Runtime  │
    │ Services  │           │  Pipeline   │             │  Services       │
    │ (管理层)  │◄─────────►│  (分析层)   │◄───────────►│  (执行层)       │
    └───────────┘           └─────────────┘             └─────────────────┘
          │                       │                             │
          └───────────────────────┼─────────────────────────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    │             │             │
              ┌─────▼────┐ ┌─────▼────┐ ┌──────▼──────┐
              │  MySQL   │ │  Redis   │ │   Nacos     │
              │ (数据层)  │ │ (缓存层) │ │ (注册中心)  │
              └──────────┘ └──────────┘ └─────────────┘
```

## 5. 部署架构

系统部署于 Kubernetes 集群，以 NGINX Ingress 为统一入口，`secflow.ai.icsl.huawei.com` 域名的路径前缀路由至对应服务。

```
┌──────────────────────────────────────────────────────────────┐
│                    NGINX Ingress Controller                   │
│  secflow.ai.icsl.huawei.com                                  │
│                                                              │
│  /                    → secflow-platform-frontend (UI)        │
│  /api/menu            → secflow-platform-menu                │
│  /api/auth            → secflow-platform-auth                │
│  /api/project         → secflow-platform-project             │
│  /api/resource        → secflow-platform-resource            │
│  /api/agent           → secflow-platform-agent               │
│  /api/workflow        → secflow-platform-workflow            │
│  /api/vuln            → secflow-platform-vuln                │
│  /api/k8s             → secflow-platform-k8s                 │
│  /api/configcenter    → secflow-platform-configcenter        │
│  /api/fileserver      → secflow-platform-fileserver          │
│  /api/packages        → secflow-platform-static-binary       │
│  /api/deploy-script   → secflow-platform-deploy-script       │
│  /api/system-analysis → secflow-platform-system-analysis     │
│  /api/app/firmware-unpacker   → secflow-app-firmware-unpacker │
│  /api/app/system-analyse      → secflow-app-system-analyse   │
│  /api/app/binary-to-source    → secflow-app-binary-to-source │
│  /api/app/entry-analyse       → secflow-app-entry-analyse    │
│  /api/app/dataflow-analyse    → secflow-app-dataflow-analyse │
│  /api/app/dataflow-vuln-scan  → secflow-app-dataflow-vuln-  │
│  /api/app/binary-security     → secflow-app-binary-security  │
│  /api/app/ipc-audit           → secflow-app-ipc-audit        │
│  /api/app/code-server         → secflow-app-code-server      │
│  /api/app/binary-evolution    → secflow-app-binary-evolution │
│  /api/dataflow-vuln-scanner   → secflow-app-dataflow-vuln-   │
│                                  scanner (legacy)            │
│  /api/app/kernel-scan         → secflow-app-kernel-scan      │
│                                                              │
│  独立域名:                                                    │
│  nacos.ai.icsl.huawei.com       → Nacos 控制台               │
│  kibana.ai.icsl.huawei.com      → Kibana (ELK)               │
│  elasticsearch.ai.icsl...com    → Elasticsearch              │
│  cloudbeaver.ai.icsl...com      → CloudBeaver (DB GUI)       │
│  sothoth.ai.icsl.huawei.com     → Sothoth v1 (legacy)        │
└──────────────────────────────────────────────────────────────┘
```

### 基础设施服务

| 目录 | 服务 | 职责 |
|:---|:---|:---|
| `00-pre-init/` | Flannel CNI, MetalLB, NGINX Ingress, cert-manager, StorageClass | 集群初始化 |
| `01-mysql-service/` | MySQL 8.0 + CloudBeaver | 主数据库与 Web 管理界面 |
| `02-vpn-access-service/` | OpenVPN | 安全远程访问 |
| `03-elk-service/` | Elasticsearch + Kibana (ECK) | 日志采集与可视化 |
| `06-nacos-registry-service/` | Nacos | 服务注册与配置管理 |
| `09-redis-service/` | Redis | 缓存与发布订阅 |
| `11-new-api-service/` | Claude Code Router + API Gateway | LLM 路由与 API 网关 |
| `12-harbor-service/` | Harbor | 容器镜像仓库 |
| `99-external-service/` | Ingress, MetalLB 暴露服务 | 外部流量入口 |

## 6. 平台服务层

平台服务负责用户管理、项目管理、Agent 生命周期和流程编排，是 SecFlow 的"操作系统"。

### 6.1 服务矩阵

| 服务 | 路由前缀 | 技术栈 | 核心职责 |
|:---|:---|:---|:---|
| `secflow-platform-auth` | `/api/auth` | Python, Flask | 用户认证、JWT 签发、RBAC 权限管理 |
| `secflow-platform-menu` | `/api/menu` | Python, Flask, Redis | 动态菜单注册、服务健康检测、成熟度分类 |
| `secflow-platform-project` | `/api/project` | Python, Flask | 项目 CRUD、项目成员管理 |
| `secflow-platform-resource` | `/api/resource` | Python, Flask | 资源/输入文件管理 |
| `secflow-platform-agent` | `/api/agent` | Python, Flask, WebSocket | Docker Compose 服务管理中心 |
| `secflow-platform-workflow` | `/api/workflow` | Python, Flask | 工作流定义与执行编排 |
| `secflow-platform-k8s` | `/api/k8s` | Python, FastAPI (uvicorn) | K8s 资源管理、Pod 终端 WebSocket |
| `secflow-platform-vuln` | `/api/vuln` | Python, FastAPI | 漏洞案例全生命周期管理 |
| `secflow-platform-fileserver` | `/api/fileserver` | Python, Flask | 文件存储与下载服务 |
| `secflow-platform-configcenter` | `/api/configcenter` | Python, Flask | 集中配置管理 |
| `secflow-platform-static-binary` | `/api/packages` | Python, Flask | 静态分析工具包分发 |
| `secflow-platform-deploy-script` | `/api/deploy-script` | Python, Flask | 部署脚本生成与管理 |
| `secflow-platform-system-analysis` | `/api/system-analysis` | Python, Flask | 系统分析任务聚合管理 |
| `secflow-platform-workflow-status` | (内部) | Python | 工作流状态追踪 |

### 6.2 menu 服务：动态菜单与服务发现

menu 服务是平台的服务目录中枢。各微服务启动时通过心跳向 menu 注册自身；menu 维护菜单树结构和服务成熟度（已上线 / 开发中 / 规划中），并定时探测各服务健康状态。前端从 menu 拉取完整导航结构，实现零配置的服务发现。

### 6.3 agent 服务：Docker Compose 管理中心

agent 服务是分析环境的编排核心。它将 Docker Compose 模板渲染为具体的分析容器实例，管理容器的创建、启停、销毁，并通过 WebSocket 转发容器终端。核心能力：

- **模板渲染**：基于 enhanced_template_manager 将抽象模板（如 dataflow-analyse worker）实例化为 `docker-compose.yaml`
- **生命周期管理**：create → start → stop → delete 完整容器生命周期
- **代理转发**：通过 EnhancedProxyManager 将容器服务暴露为 HTTP 代理，支持 WebSocket 透传
- **分布式锁**：基于 Redis 的 deploy/undeploy 互斥锁，多副本安全
- **文件上传**：支持 zip/tar/tar.gz/tar.bz2/tar.xz 等多种压缩格式

## 7. 分析流水线层

分析层是 SecFlow 的核心价值创造单元。各分析服务通过统一的 REST API（FastAPI + uvicorn）和 SSE 事件流暴露能力，由 `secflow-app-binary-security` 统一编排为端到端流水线。

### 7.1 端到端流水线（Full Pipeline）

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        binary-security 编排器                             │
│                                                                          │
│  模式: barrier（逐阶段屏障） / mixed_streaming（混合流式）                  │
│                                                                          │
│  ┌──────────────────┐    ┌──────────────────┐    ┌───────────────────┐  │
│  │ firmware-unpacker│───►│ system-analyse   │───►│ binary-to-source  │  │
│  │ 固件解包          │    │ 系统威胁分析      │    │ 二进制溯源        │  │
│  └──────────────────┘    └──────────────────┘    └────────┬──────────┘  │
│                                                           │              │
│                              barrier ──── mixed_streaming ─┤             │
│                                                           │              │
│  ┌──────────────────┐    ┌──────────────────┐    ┌───────▼──────────┐   │
│  │ dataflow-vuln-   │◄───│ dataflow-analyse │◄───│ entry-analyse    │   │
│  │ scan (漏洞挖掘)   │    │ 数据流分析        │    │ 入口分析          │   │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘   │
│                                                                          │
│  mixed_streaming 模式下，后三段以 item（模块/入口）为单位流式推进：        │
│  一个模块的 binary-to-source 产出后，立即触发其 entry-analyse，           │
│  完成后立即触发 dataflow-analyse，再触发 dataflow-vuln-scan。            │
└──────────────────────────────────────────────────────────────────────────┘
```

### 7.2 firmware-unpacker：固件解包引擎

**定位**：将原始固件镜像解包为可分析的文件系统。

**核心能力**：
- 支持多种固件格式（bin, img, zip, tar 等）
- 基于 pi Agent 的交互式解包策略生成
- 演化引擎（evolution_engine）：基于历史解包结果优化策略
- 工具分发（tool_dispatcher）：按需安装解包工具（binwalk, jefferson 等）
- 解包产物自动索引

**架构**：FastAPI 微服务，解包任务在独立 worker 线程/进程执行，通过 SSE 推送事件进度。

### 7.3 system-analyse：系统威胁分析

**定位**：对解包后的文件系统执行四阶段流水线：模块分类 → 精细化拆分 → STRIDE 威胁分析 → 汇总报告。

**流水线阶段**：

```
Stage 0: 预处理
├── 文件过滤（类型 + 架构）
├── 探索目录（MiniMax 关键词提取）
└── 预扫描（词频统计 + 黑名单）

Stage 1: 全局分类（Worker + Judge 循环）
├── Worker: 创建 modules/ 目录树，按功能分类
└── Judge: 零遗漏铁律验证（Missing > 0 → 0 分）

Stage 2: 模块精细化拆分
├── 主从模式（文件数 > 20）
│   ├── Master: 调度 Sub-Worker
│   └── Sub-Worker: 分析单文件/单子模块
└── asyncio.Queue 并发控制

Stage 3: STRIDE 威胁分析
├── 每个模块独立分析
├── 安全关注点过滤（仅保留安全相关模块）
└── 自省循环（self_reflection → refine → re-analyse）

Stage 4: 汇总报告
├── 完整性检查
└── 最终漏洞发现报告
```

**关键设计**：
- **校验矩阵（Checkpoint）**：每个阶段产出可通过 checkpoint 续跑
- **PiFatalError 熔断**：pi Agent 内部致命错误时立即终止，避免无效计算
- **并行调度**：Stage 2 支持 `parallel_modules` 路并行，Stage 3 以模块为粒度并行
- **安全过滤链**：`s1_security_filter` → `s0_unknown_checker` → `s0_type_classify` → `s2_refine` → `s3_analyse`，逐层减少无效分析

### 7.4 binary-to-source：二进制溯源

**定位**：对 system-analyse 识别出的二进制文件执行反编译与源码对照，将二进制分析产物转换为可被后续阶段消费的结构化信息。

**核心能力**：
- 基于 IDA Pro / Ghidra 的自动反编译
- 二进制与源码的对应关系建立
- 符号恢复与函数边界识别

### 7.5 entry-analyse：外部入口分析

**定位**：扫描模块所有代码文件，识别外部输入进入该模块的总入口函数。

**核心概念 — 外部入口**：外部数据第一次进入该模块的函数，分两类：
- **被动回调型**：被框架/分发表直接调用，数据由参数传入
- **主动拉取型**：函数内部调用 `recv`/`read`/`mmap` 等系统调用

**流水线架构**：

```
R1 函数提取
├── 扫描源文件，提取函数定义（名称、签名、行号）
└── 输出 functions/ 目录

R2 外部输入分析（Worker + Judge 循环）
├── Worker: 逐文件分析外部入口
│   ├── Round 1: 概览 → 逐文件分析 → 汇总 entry-list.md
│   └── Round N: 注入 Judge 反馈 → 重新分析
└── Judge: 读源码 + grep 验证每个入口
    ├── PASS (≥ pass_threshold) + ≥ min_rounds → 完成
    └── FAIL → 注入 feedback → 下一轮

R3 文件级过滤
├── 验证入口函数是否存在于源码中
└── 过滤误报和重复

R4 模块级汇总
├── 跨文件去重
├── 入口优先级排序（P = 确定为入口, A = 潜在入口）
└── 输出 functions.list (JSON)
```

**关键设计**：
- **角色分离**：支持 scheduler + worker 双角色部署，scheduler 负责任务分派，worker 并发执行
- **租约续期**：长时间运行的分析任务通过 lease_renewer 保持心跳
- **即时取消**：内置 cancel HTTP server（端口 3001），支持内存级任务取消

### 7.6 dataflow-analyse：数据流污点分析

**定位**：从 entry-analyse 产出的入口函数出发，递归追踪外部输入在调用链中的传播路径。

**架构**：

```
Orchestrator
├── execute_recursive(depth)
│   ├── Round 1..N (max_rounds=-1 → ∞)
│   │   ├── Workers × W (并行)
│   │   │   └── 分析当前函数的污点传播
│   │   ├── Judges × J (并行)
│   │   │   └── 验证 Worker 输出的完整性和准确性
│   │   └── 通过 or 继续 → 注入 feedback
│   │
│   ├── 解析 callee 列表
│   ├── 并行递归 (asyncio.gather)
│   │   ├── callee_1 → execute_recursive(depth+1)
│   │   ├── callee_2 → execute_recursive(depth+1)
│   │   └── callee_N → execute_recursive(depth+1)
│   │
│   └── Merge Agent: 合并所有 dataflow-*.md
│
└── PerTaintWorkflow: 多污点变量独立追踪
```

**核心组件**：

| 组件 | 职责 |
|:---|:---|
| `orchestrator.py` | BFS 队列 + Worker Pool 递归分析调用链 |
| `runner.py` | 调用 pi 进程执行单个 Agent，流式输出 + 重试 |
| `taint_workflow.py` | 单污点变量追踪工作流，多污点并行 |
| `judge_runner.py` | Judge Mixin，三级评审闭环 |
| `parsers.py` | 解析 callee 列表、污点列表、评估结果 |
| `prompt_builder.py` | 动态构建 Worker/Judge/Eval/Summary Prompt |
| `cpp_resolver.py` | C++ 符号解析、函数定义查找 |

**设计原则**：
- **无上限轮次**：`max_rounds=-1`，Judge 不通过则无限重试，直到通过或超时
- **递归深度控制**：`max_depth` 限制调用链分析深度
- **Worker 并行度**：可配置并发 Worker 数，同一函数的多轮分析共享上下文
- **能力模式**：支持 full / worker-only / judge-only / control-plane 四种运行时角色

### 7.7 dataflow-vuln-scan：数据流漏洞挖掘

**定位**：在 dataflow-analyse 的污点传播路径上，执行漏洞识别与验证。

**与 dataflow-analyse 的差异**：
- 共享相同的编排架构（Orchestrator + Worker/Judge + BFS 递归）
- 不同的 prompt 策略：聚焦于安全漏洞模式识别而非污点传播路径
- 新增漏洞图谱服务（vuln_graph_service）：构建漏洞与代码位置的关系图
- 新增漏洞存储（vuln_store）：持久化漏洞发现，支持去重和CVE归属

### 7.8 dataflow-vuln-scanner（legacy）：传统扫描器

**定位**：JSON 配置驱动的可编排 AI 工作流引擎，通过 Python 插件实现业务逻辑。是新一代 dataflow-vuln-scan 的前身。

**架构特点**：
- JSON 配置定义智能体、工作流、角色和评审策略
- Python 插件化实现业务逻辑扩展
- 多智能体协同 + 三级评审闭环
- 内置 Dashboard 可视化

### 7.9 dataflow-vuln-scanner-evolver：扫描器进化工具

**定位**：交互式进化工具，通过 pi agent 迭代优化 dataflow-vuln-scanner 的漏洞挖掘能力。

**工作流**：
1. 选定漏洞案例作为基准测试集
2. 启动交互式 pi agent 会话
3. 进化 agent 生成优化策略 MD 文档（skills + memory）
4. 注入文档到 dataflow-vuln-scanner，replay 原始任务
5. 监控进度，收集结果
6. 用户评估，给出调整方向
7. 循环迭代直到满意

### 7.10 kernel-scan：内核漏洞扫描

**定位**：面向 Linux 内核源码的独立分析服务，支持攻击入口发现、漏洞审计和 PoC 验证。

**流水线模式**：

| 模式 | 阶段 | 输入 |
|:---|:---|:---|
| `entry_only` | 入口发现 | 内核目录 |
| `audit_only` | 漏洞审计 | 入口清单 |
| `poc_only` | PoC 验证 | 内核目录 + 审计报告，需 ADB |
| `entry_audit_poc` | 全流程 | 内核目录 |

**技术栈**：FastAPI + SQLite，通过 subprocess 调用 pi agent 脚本（`ask_claude_entry.py` / `ask_claude_kernaudit_v2.py` / `ask_claude_poc.py`），内置 Android ADB 工具链。

### 7.11 ipc-audit：IPC 通信审计

**定位**：面向组件间通信（IPC）的专项审计服务，支持自定义 provider 扩展。

**架构**：FastAPI 微服务，workspace → providers → stages → artifacts 层次结构。
- **Provider 系统**：可注册外部分析 provider（如 IDA Pro 分析结果）
- **三阶段流水线**：graph（构建 IPC 通信图）→ audit（审计通信漏洞）→ poc（PoC 验证）
- **Provider runtime**：独立的 PoC 执行环境

## 8. Agent 执行层

### 8.1 agent-helper：远程调试容器

**定位**：部署于目标分析环境的 sidecar 容器，提供完整的交互式调试能力。

**核心组件**：

| 组件 | 端口 | 用途 |
|:---|:---|:---|
| Flask API | 20001 | 远程命令执行 |
| ttyd Web Terminal | 20002 | 基于 Web 的终端访问 |
| code-server | 20003 | VS Code Web IDE |
| agent_ai_service | (内部) | AI Agent 管理与适配 |

**agent_ai_service 架构**：
- **适配器层**：支持 Claude、Codex、OpenCode 等多种 AI Agent 后端
- **A2A（Agent-to-Agent）通信**：基于 Google A2A 协议的多 Agent 协作
- **Session Pipe**：Agent 会话的管道化管理，支持创建、暂停、恢复
- **Command Executor**：安全命令执行代理
- **Persistence**：文件级会话持久化

**process_monitor_service**：进程监控服务，API 驱动的进程列表查询和资源监控。

### 8.2 tetragon-monitor：运行时安全监控

**定位**：基于 Cilium Tetragon 的 eBPF 运行时安全监控，部署于 Kubernetes 集群。

**能力矩阵**：

| Tracing Policy 分类 | 监控目标 |
|:---|:---|
| `process/` | 进程执行、ELF 加载 |
| `file/` | 文件访问、挂载操作 |
| `network/` | TCP 连接、数据报通信 |
| `capability/` | 进程 capability 变更、ptrace 调用 |
| `credentials/` | 凭证变更、权限提升 |
| `namespace/` | 命名空间操作、pivot_root |
| `kernel/` | 内核模块加载、BPF 程序检查 |

**输出**：事件推送至 Elasticsearch，通过 Kibana 可视化。

### 8.3 MCP 服务

**定位**：基于 Model Context Protocol (MCP) 的工具服务，为 AI Agent 提供标准化的外部能力接入。

| 服务 | 用途 |
|:---|:---|
| `mcp-ssh` | SSH 远程命令执行工具 |
| `mcp-ssh-server` | SSH 服务端 MCP 封装 |
| `mcp-inspector` | MCP 服务调试与检查工具 |

## 9. 前 端

**技术栈**：React 19 + TypeScript + Vite

**核心依赖**：
- `@xyflow/react`：流程图可视化（数据流图、调用链图）
- `@xterm/xterm`：Web 终端（Pod 终端、容器终端）
- `@monaco-editor/react`：代码编辑器（源码查看、报告编辑）
- `recharts`：指标图表（任务统计、漏洞趋势）
- `react-markdown` + `remark-gfm`：Markdown 报告渲染

**路由结构**：基于 `react-router-dom` v7，单页应用，通过 NGINX 反向代理到各后端服务的 `/api/*` 路径。

## 10. 跨切面设计

### 10.1 统一的运行时模式

多个分析服务（dataflow-analyse、dataflow-vuln-scan、entry-analyse、system-analyse）共享一套运行时架构：

```
┌──────────────────────────────────────────────────────┐
│              runtime_bootstrap (启动时)               │
│                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │ control-plane│  │  scheduler   │  │   worker    │ │
│  │ API 服务 +   │  │  任务分派    │  │  Agent 执行 │ │
│  │ 任务管理     │  │  队列管理    │  │  结果回写   │ │
│  └──────────────┘  └──────────────┘  └────────────┘ │
│                                                      │
│  共享基础设施:                                         │
│  • config_service (Nacos/本地 YAML)                   │
│  • llm_provider_sync (AI 提供商配置同步)              │
│  • session_index (pi session 索引与检索)              │
│  • agent_observability (Agent 可观测性)               │
│  • worker_slot_service (Worker 并发槽位管理)          │
│  • registry_service (服务注册与心跳)                   │
│  • prompt_service (Prompt 模板 CRUD)                  │
└──────────────────────────────────────────────────────┘
```

### 10.2 统一通信模式

所有分析服务对外暴露一致的 API 范式：

```
POST   /api/app/{service}/tasks         创建任务
GET    /api/app/{service}/tasks         任务列表
GET    /api/app/{service}/tasks/{id}    任务详情
POST   /api/app/{service}/tasks/{id}/cancel  取消
POST   /api/app/{service}/tasks/{id}/restart 重启
POST   /api/app/{service}/tasks/{id}/resume  续跑
DELETE /api/app/{service}/tasks/{id}         删除

GET    /api/app/{service}/tasks/{id}/stream  SSE 事件流

CRUD   /api/app/{service}/prompts/*     Prompt 管理
GET    /api/app/{service}/generate-prompt  自动生成 prompt
GET    /api/app/{service}/health        健康检查
GET    /api/app/{service}/metrics       指标查询
```

### 10.3 统一产物契约

分析阶段之间通过文件系统传递结构化产物，不通过 API 传递大数据：

```
/data/files/{project_id}/{service}/
├── input/              ← 上游产物（软链接或拷贝）
├── output/             ← 本阶段最终产物
│   ├── flag            ← 0=失败 / 1=成功
│   └── result.json     ← 结构化结果
├── run/                ← 中间产物
│   ├── workspace/      ← 分析工作区
│   └── sessions/       ← pi session 文件
└── events/             ← 任务事件流日志
```

### 10.4 Worker + Judge 闭环

多个分析服务（entry-analyse、dataflow-analyse、dataflow-vuln-scan、system-analyse）采用相同的 Worker + Judge 迭代校验模式：

```
          ┌─────────┐     产物      ┌─────────┐
          │ Worker  │──────────────►│  Judge  │
          │ (Agent) │               │ (Agent) │
          └────┬────┘               └────┬────┘
               │       feedback          │
               │◄────────────────────────┘
               │                    (不通过时)
               │
          ┌────▼────┐
          │ 下一轮   │
          │ Worker  │  (注入 feedback + 源码上下文)
          └─────────┘
```

- **怀疑优先**：Judge 独立上下文，不共享 Worker 状态，默认立场是"不完全正确"
- **铁律验证**：Judge 通过具体代码引用来验证 Worker 的每个断言
- **无上限**：回合数未达上限时，不允许提前终止（`min_rounds` 约束）
- **评分制**：Judge 输出结构化评分（通过/不通过 + 详细理由 + 改进建议）

### 10.5 多维度并发控制

系统在多层级实现并发控制：

| 层级 | 控制点 | 机制 |
|:---|:---|:---|
| 流水线级 | `binary-security` | 阶段屏障 / mixed_streaming 模式 |
| 阶段级 | 各分析服务 | 服务内 `worker_slot_service` 并发槽位 |
| Agent 级 | Orchestrator | `Worker × W` / `Judge × J` 并行度 |
| 实例级 | Docker Compose | Agent 容器实例数 |
| 平台级 | `platform-agent` | Redis 分布式锁 + 连接池 |

### 10.6 CI/CD 流水线

GitHub Actions 自动构建和推送 Docker 镜像：

- **触发条件**：推送到 `v2.*` 分支
- **多架构**：`linux/amd64` + `linux/arm64`
- **双注册中心**：Docker Hub (`runshine0819/*`) + GHCR (`ghcr.io/runshine/*`)
- **标签策略**：`latest` + 日期格式 `YYYYMMDD`
- **覆盖范围**：30+ 个工作流文件，覆盖全部微服务和基础镜像

## 11. 关键数据流

### 11.1 端到端分析数据流

```
用户上传固件
    │
    ▼
platform-resource (接收文件，存入 fileserver)
    │
    ▼
binary-security (创建总任务，分派各阶段子任务)
    │
    ▼
firmware-unpacker (解包 → 文件系统 tree)
    │ 产物: 文件列表 + 二进制/脚本/配置分类
    ▼
system-analyse (模块分类 → 威胁分析)
    │ 产物: modules/ 目录树 + 威胁报告
    ▼
binary-to-source (二进制 → 反编译 + 源码对照)
    │ 产物: 源码路径映射 + 符号信息
    ▼
entry-analyse (扫描入口函数)
    │ 产物: functions.list (JSON)
    ▼
dataflow-analyse (追踪污点调用链)
    │ 产物: dataflow report (Markdown)
    ▼
dataflow-vuln-scan (识别漏洞模式)
    │ 产物: 漏洞列表 + 漏洞图谱
    ▼
platform-vuln (漏洞案例管理、去重、优先级排序)
    │
    ▼
secflow-frontend (可视化展示)
```

### 11.2 Agent 实例创建数据流

```
用户选择分析模板
    │
    ▼
platform-agent API (POST /api/agent/deploy/create)
    │
    ├── EnhancedTemplateManager: 模板渲染 → docker-compose.yaml
    ├── RedisManager: 获取分布式锁
    ├── AgentManager: docker-compose up
    ├── EnhancedProxyManager: 注册代理路由
    └── MenuRegistryService: 注册到 menu 服务
    │
    ▼
agent-helper 容器启动
    │
    ├── Flask API (20001): 命令执行
    ├── ttyd (20002): Web Terminal
    ├── code-server (20003): Web IDE
    ├── agent_ai_service: AI Agent 后端
    └── process_monitor_service: 进程监控
```

## 12. 设计原则

| # | 原则 |
|:---|:---|
| 1 | **阶段解耦，产物契约** — 分析阶段通过文件系统传递结构化产物，不通过 API 耦合 |
| 2 | **Worker + Judge 闭环** — 分析由 Worker 产出、Judge 独立校验，不通过则无限迭代 |
| 3 | **怀疑优先** — Judge 默认假设 Worker 产出不完全正确，需代码证据说服 |
| 4 | **能力可组合** — 每个分析服务独立部署、独立演进出，平台通过编排器（binary-security）组合 |
| 5 | **运行时可拆分** — 单个分析服务支持 control-plane / scheduler / worker 多角色部署 |
| 6 | **一容器一职责** — 分析计算在独立容器中执行，由 platform-agent 管理生命周期 |
| 7 | **统一范式，降低认知负担** — 所有分析服务共享相同的 API 风格、产物结构、事件模型 |
| 8 | **确定性路由 + AI 判断** — 流水线编排是确定性的，Agent 只在需要语义判断时介入 |
| 9 | **全量可观测** — 每个阶段、每个任务、每个 Agent 调用都有 SSE 事件流、日志和指标 |
| 10 | **渐进式部署** — 从单体到微服务可按需演进，服务通过 menu 注册实现运行时发现 |

## 13. 技术栈总览

| 层次 | 技术 |
|:---|:---|
| **编排** | Kubernetes, Docker Compose, MetalLB, NGINX Ingress |
| **后端框架** | Python Flask (平台服务), Python FastAPI/uvicorn (分析服务) |
| **AI Agent** | pi (多智能体 CLI 框架), Claude/Codex/OpenCode 适配 |
| **数据库** | MySQL 8.0 (主库), Redis (缓存/锁/发布订阅), SQLite (kernel-scan) |
| **注册中心** | Nacos |
| **日志** | Elasticsearch + Kibana (ECK Operator) |
| **镜像仓库** | Harbor |
| **前端** | React 19 + TypeScript + Vite |
| **CI/CD** | GitHub Actions, Multi-arch Docker Build |
| **运行时安全** | Cilium Tetragon (eBPF) |
| **通信协议** | REST (HTTP/1.1), WebSocket, SSE, A2A (Agent-to-Agent) |
| **MCP** | Model Context Protocol (SSH 工具) |
