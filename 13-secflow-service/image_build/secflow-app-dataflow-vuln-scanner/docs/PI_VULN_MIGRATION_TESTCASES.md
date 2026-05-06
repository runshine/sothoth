# SecFlow AI Agent Framework `pi-vuln` 迁移测试用例

## 1. 测试目标

验证 `secflow-platform-ai-agent-framework` 在切换为 `pi-vuln` 核心引擎后，仍然满足以下能力：

1. `pi-vuln` JSON 定义成为唯一真相源。
2. 同时支持 `REST` 常驻服务模式与 `CLI` 单次执行模式。
3. 保持现有前端信息架构与 REST API 前缀 `/api/ai-agent-framework` 不变。
4. 保持 MySQL 持久化、多 Pod 抢占调度、PVC 工作目录与 fileserver 项目目录策略。
5. 支持批量 trigger、多任务组合工作流执行、执行事件落盘与数据库观测。

## 2. 测试范围

| 范围 | 说明 |
| --- | --- |
| 定义校验 | `pi-vuln` schema、入口工作流、工作流引用、循环引用 |
| 执行模式 | `serve` 与 `run` 双模式 |
| REST 服务 | definition、trigger、execution、scheduler 接口 |
| 执行引擎 | atomic/composite、批量任务、review、plugin、observer |
| 调度 | MySQL 抢占、多 Pod owner 绑定、租约与取消 |
| 持久化 | 项目级 `AI_AGENT_FRAMEWORK` 子项目、PVC、任务目录、结果目录 |
| 前端 | 定义模板、详情页、JSON、流程图、原子工作流展开 |
| 发布验证 | GitHub Actions、镜像更新、K8S rollout、日志与健康检查 |

## 3. 环境前置条件

| 项目 | 要求 |
| --- | --- |
| 数据库 | MySQL 可用，相关表已初始化 |
| K8S | `secflow-ns` 命名空间可用，Deployment/Service 已部署 |
| PVC | `secflow-platform-fileserver-data-nfs-pvc` 已挂载到 `/data` |
| Auth | `secflow-platform-auth` 可访问 |
| Fileserver | fileserver API 可访问，项目下允许自动创建 `AI_AGENT_FRAMEWORK` 子项目 |
| 镜像 | GitHub Actions 可推送 `ghcr.io/runshine/secflow-platform-ai-agent-framework` |

## 4. 核心测试用例

### 4.1 定义校验

| 用例 ID | 场景 | 步骤 | 预期结果 |
| --- | --- | --- | --- |
| TC-DEF-001 | 保存合法 `pi-vuln` 定义 | 提交完整 `version/global/agents/plugins/workflows/execution` JSON | 创建成功，返回 `root_workflow_id`、`entry_input_task_type`、`final_output_task_type` |
| TC-DEF-002 | 拒绝旧 schema | 提交旧版 `atomic_workflows/composite_workflows/root_workflow_id` JSON | 返回 `422`，错误信息明确指出 schema 不合法 |
| TC-DEF-003 | 入口必须为 composite | `execution.entry_workflow` 指向 atomic | 返回 `422` |
| TC-DEF-004 | 坏引用校验 | `stage.workflow_ref` 引用不存在 workflow | 返回 `422` |
| TC-DEF-005 | composite 循环引用 | A 引 B，B 引 A | 返回 `422` |
| TC-DEF-006 | 首尾类型推导 | 合法 composite 链包含多层嵌套 | 成功推导入口/终态任务类型摘要 |

### 4.2 REST 定义管理

| 用例 ID | 场景 | 步骤 | 预期结果 |
| --- | --- | --- | --- |
| TC-API-001 | 创建工作流定义 | `POST /workflow-definitions` | 返回 `200/201`，definition 入库 |
| TC-API-002 | 更新定义并生成版本 | `PUT /workflow-definitions/{id}` | 版本号递增，旧版本可查询 |
| TC-API-003 | 激活/停用定义 | 调用 `activate/deactivate` | `is_active` 正确切换 |
| TC-API-004 | 权限隔离 | 非项目用户访问定义 | 返回 `403` |

### 4.3 Trigger 与输入任务

| 用例 ID | 场景 | 步骤 | 预期结果 |
| --- | --- | --- | --- |
| TC-TRG-001 | 批量 trigger | 一个 trigger 提交多个输入任务 | 成功创建一个 TriggerTask 和一个 WorkflowExecution |
| TC-TRG-002 | 自动注入入口任务类型 | 前端不传 `task_type` 创建 trigger | 后端自动使用 `entry_input_task_type` 写入任务 |
| TC-TRG-003 | 错误任务类型兼容校验 | 传入与入口类型不一致的 `task_type` | 返回 `422` |
| TC-TRG-004 | 上传文件/文件夹 | 通过 fileserver 上传后创建 trigger | 上传文件被复制到任务输入目录 `input/assets/` |
| TC-TRG-005 | 任务预览 | 前端触发前查看最终 JSON | 预览内容与实际写入 `tasks.json` 一致 |

### 4.4 项目目录与持久化

| 用例 ID | 场景 | 步骤 | 预期结果 |
| --- | --- | --- | --- |
| TC-FS-001 | 自动创建子项目 | 首次在项目中触发 AI 工作流 | 自动创建 fileserver 子项目 `AI_AGENT_FRAMEWORK` |
| TC-FS-002 | 定义级目录结构 | 同一 workflow definition 多次触发 | 文件落到 `workflow-definitions/<definition>/trigger-tasks/<trigger>/executions/<execution>/` |
| TC-FS-003 | 任务独立目录 | 一个 execution 内有多个初始任务 | 每个任务都有独立目录，输入文件落在各自目录下 |
| TC-FS-004 | PVC 持久化 | Pod 重启后检查已完成 execution 工件 | 工件仍存在于 `/data` 挂载目录 |

### 4.5 执行引擎与 `pi-vuln` 适配

| 用例 ID | 场景 | 步骤 | 预期结果 |
| --- | --- | --- | --- |
| TC-ENG-001 | REST 模式运行 | 通过 trigger 启动 execution | 服务层动态覆盖 `execution_id/input_task/output_dir/runtime_mode`，静态定义不被改写 |
| TC-ENG-002 | CLI 模式运行 | `python -m app.main run --config <json>` | 成功执行，退出码与 `on_completion` 配置一致 |
| TC-ENG-003 | CLI 保留工作区 | 使用 `--keep-workspace` | 执行后 workspace 保留 |
| TC-ENG-004 | CLI 清理工作区 | 使用 `--clean-workspace` | 执行完成后 workspace 被清理 |
| TC-ENG-005 | 批量任务入口 | REST 提交多个初始任务 | `run_tasks(...)` 成功驱动组合工作流 |
| TC-ENG-006 | observer 双写 | 执行 workflow | 本地 recorder 与 DB `WorkflowExecutionEvent` 同步写入 |
| TC-ENG-007 | 取消边界 | execution 运行中请求取消 | 在 stage/plugin/review/cycle 边界优雅停止并更新状态 |

### 4.6 Plugin / Review / Summary

| 用例 ID | 场景 | 步骤 | 预期结果 |
| --- | --- | --- | --- |
| TC-PLG-001 | 插件 6 种状态 | 构造返回不同 `PluginResultCode` 的插件 | 引擎控制流符合预期 |
| TC-PLG-002 | summary 产物 | worker 完成后执行 summary | 生成 summary 与 results 产物 |
| TC-REV-001 | global review fail 回流 | global advisor 返回失败 | 当前 cycle 终止并回流 worker |
| TC-REV-002 | result review fail 聚合 | 某结果 reviewer 失败 | 当前结果停止后续 reviewer，失败反馈聚合回流 |
| TC-REV-003 | result review pass 缓存 | 结果在前一轮已通过 | 后续轮次默认跳过，不重复评审 |

### 4.7 多 Pod 调度

| 用例 ID | 场景 | 步骤 | 预期结果 |
| --- | --- | --- | --- |
| TC-SCH-001 | 单 execution 单 owner | 两个 Pod 同时扫描 pending execution | 仅一个 Pod 抢占成功 |
| TC-SCH-002 | capacity 限流 | 某 Pod `running_count == capacity` | 不再领取新任务 |
| TC-SCH-003 | definition 并发上限 | workflow definition 达到 `max_concurrency` | 新 trigger 保持 pending |
| TC-SCH-004 | draining 行为 | 将 worker 置为 `draining` | 不再抢新任务，但已有 execution 正常跑完 |
| TC-SCH-005 | lease 超时 | owner Pod 不续租 | execution 标记为 `orphaned` 或保留人工处理状态 |

### 4.8 前端回归

| 用例 ID | 场景 | 步骤 | 预期结果 |
| --- | --- | --- | --- |
| TC-FE-001 | AI 工作流菜单可见 | 打开前端侧边栏 | 一级菜单 `AI工作流` 正常显示 |
| TC-FE-002 | 定义列表与详情 | 点击某个 workflow | 先进入列表，再进入详情页多 tab 布局 |
| TC-FE-003 | JSON 模板切换为 `pi-vuln` | 新建定义 | 默认模板为 `version/global/agents/plugins/workflows/execution` |
| TC-FE-004 | 流程图解析 composite | 查看 overview 流程图 | 根节点来自 `execution.entry_workflow` |
| TC-FE-005 | 原子工作流展开 | 点击 atomic 节点 | 主画布展开 pre/plugin/worker/review/post 流程 |
| TC-FE-006 | 任务触发页 | 选择 definition 并创建 trigger | 不再暴露任务类型输入，入口/终态类型只读展示 |

### 4.9 发布与运维验证

| 用例 ID | 场景 | 步骤 | 预期结果 |
| --- | --- | --- | --- |
| TC-OPS-001 | GitHub Actions 构建 | push 到 `v2.*` | `build-secflow-platform-ai-agent-framework-image` 成功 |
| TC-OPS-002 | 镜像升级 | Deployment rollout restart 或 set image | Pod 拉起新 digest |
| TC-OPS-003 | K8S 健康检查 | 访问 `/health` 和 `/ready` | 返回成功 |
| TC-OPS-004 | 日志无启动错误 | 检查 Pod 日志 | 无 `ERROR/Exception/Traceback/failed` 级别错误 |

## 5. 回归优先级建议

| 优先级 | 必测内容 |
| --- | --- |
| P0 | 定义创建、trigger 创建、execution 跑通、Pod 健康、日志无报错 |
| P1 | 多任务 trigger、事件查询、artifact 查询、前端流程图、PVC 目录结构 |
| P2 | 多 Pod 并发、drain、cancel、CLI 双模式、异常路径 |

## 6. 发布验收清单

1. GitHub Actions run 成功，镜像 manifest 已发布。
2. K8S Deployment 已滚动到新 ReplicaSet，Pod 使用新 image digest。
3. `/api/ai-agent-framework/health` 与 `/api/ai-agent-framework/ready` 返回成功。
4. Pod 日志无启动失败、导入失败、配置校验失败、数据库连接失败。
5. 前端工作流定义页可正常渲染 `pi-vuln` JSON 与流程图。
6. 至少完成一条 definition 创建、trigger 创建、execution 事件查询的冒烟链路。
