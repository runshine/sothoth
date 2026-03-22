# SecFlow 漏洞生命周期编排引擎总览

这份文档用于快速理解 `secflow-platform-vuln` 的系统定位、架构边界和 API 面。

## 1. 一句话概括

`secflow-platform-vuln` 是“漏洞生命周期编排引擎”，不是漏洞分析器。

它负责：

- 管理漏洞 `Case`
- 注册能力服务
- 派发 `Action`
- 收敛 `Result`
- 自动推进阶段
- 生成并管理人工任务
- 提供平台级前端工作台和项目运营视图

## 2. 三层模型

### 2.1 平台编排层

- 生命周期阶段
- 自动规则
- `Action` 派发
- 人工任务
- 决策收敛

### 2.2 能力执行层

- AI 分析
- 静态分析
- 逆向分析
- 运行时验证
- POC/EXP
- 仿真
- 反馈处理

### 2.3 数据与展示层

- `Case`
- `Result`
- `ActionExecution`
- 时间线
- 工作台视图
- 附件元数据

## 3. 核心实体

- `Case`
  - 平台管理单元
- `WorkflowRun`
  - 当前生命周期运行实例
- `ActionExecution`
  - 平台派发的动作
- `Result`
  - 外部服务提交的结果
- `ManualTask`
  - 自动化和人工协作桥梁
- `ServiceRegistry / ServiceCapability`
  - 能力服务和 capability 声明
- `StageHistory / CaseEvent`
  - 审计和时间线

## 4. API 结构

### 4.1 健康

- `GET /api/vuln/health`
- `GET /api/vuln/ready`

### 4.2 服务注册

- `POST /api/vuln/services/register`
- `POST /api/vuln/services/heartbeat/{service_id}`
- `DELETE /api/vuln/services/unregister/{service_id}`
- `GET /api/vuln/services`
- `GET /api/vuln/services/{service_id}`

### 4.3 Case

- `POST /api/vuln/cases`
- `GET /api/vuln/cases`
- `GET /api/vuln/cases/{case_id}`
- `GET /api/vuln/cases/{case_id}/timeline`

### 4.4 工作台

- `GET /api/vuln/cases/ops/dashboard/overview`
- `GET /api/vuln/cases/ops/manual-tasks`
- `GET /api/vuln/actions/ops/queue`

### 4.5 生命周期操作

- `POST /api/vuln/cases/{case_id}/manual-tasks`
- `POST /api/vuln/cases/{case_id}/manual-tasks/{task_id}/status`
- `POST /api/vuln/cases/{case_id}/stage-transition`
- `POST /api/vuln/cases/{case_id}/decisions`
- `POST /api/vuln/cases/{case_id}/actions/dispatch`
- `GET /api/vuln/cases/{case_id}/recommended-actions`
- `POST /api/vuln/cases/{case_id}/orchestrate/auto`

### 4.6 Action

- `POST /api/vuln/actions/{action_id}/callback`
- `POST /api/vuln/actions/{action_id}/control`
- `POST /api/vuln/actions/mock-dispatch/{case_id}`

## 5. 当前前端工作台

前端已实现漏洞引擎工作台，围绕这些工作区组织：

- 总览
- Case 运行
- 能力服务
- 人工任务
- Action 队列

工作台支持：

- 创建 Case
- 注册服务
- 查看推荐动作
- 一键自动编排
- 查看时间线和结果
- 人工裁决
- Action 重试/取消

## 6. 存储与部署

- 数据库存元数据
- 文件设计使用共享 RWX PVC
- 未来预留 S3/对象存储扩展
- 独立 API 前缀：`/api/vuln`
- 已支持 k8s 多实例部署

## 7. 当前最重要的设计原则

- 平台只做引擎，不做能力本身
- 平台不实现去重，只预留去重框架
- 平台统一存元数据，不强耦合漏洞细分结构
- 平台允许自动化与人工共同驱动生命周期
- 平台优先做通用 `Action/Result` 契约
