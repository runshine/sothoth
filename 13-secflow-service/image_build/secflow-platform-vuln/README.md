# SecFlow 漏洞生命周期编排引擎

`secflow-platform-vuln` 是 SecFlow 平台里的漏洞生命周期编排引擎。它不是扫描器、验证器、POC 生成器，而是平台侧的运行中枢：

- 统一注册外部漏洞能力微服务
- 统一管理漏洞 `Case`
- 统一编排生命周期阶段和 `Action`
- 统一汇总 `Result`、时间线、人工任务和决策
- 统一承载平台级附件与后续反馈闭环

当前代码、前端工作台、k8s 部署和 GitHub Actions 镜像构建已经连成闭环。

## 当前实现范围

当前已落地能力：

- 漏洞 `Case` 创建、查询、详情、时间线
- 能力服务注册、心跳、注销、能力声明
- 生命周期最小引擎
- `Action` 路由派发、自动推荐、自动编排
- 外部结果回调、结果收敛、自动推进规则
- 人工任务创建、流转、人工裁决
- 项目级运营视图接口
- 平台独立附件元数据模型
- 前端漏洞引擎工作台
- k8s 多实例部署与共享 PVC
- x64/aarch64 GitHub Actions 多架构镜像构建

当前明确不做：

- 平台侧去重逻辑
- 平台侧扫描、验证、POC/EXP 生成
- 强耦合的源码/二进制漏洞模型
- S3 存储后端实现
- 复杂 DSL 工作流引擎

## 核心定位

平台负责：

- 编排
- 状态机
- 任务分发
- 结果汇总
- 人工接管
- 审计追踪

外部能力服务负责：

- 分析
- 验证
- POC/EXP
- 仿真
- 反馈处理

## 目录结构

```text
secflow-platform-vuln/
├── app/
│   ├── api/
│   ├── models/
│   ├── services/
│   ├── config.py
│   ├── exception.py
│   ├── main.py
│   └── schemas.py
├── config.yaml
├── doc/
│   ├── API.md
│   ├── ARCHITECTURE.md
│   ├── SYSTEM_SUMMARY.md
│   └── TEST_PLAN.md
├── tests/
├── Dockerfile
└── requirements.txt
```

## 主要 API

基础健康：

- `GET /api/vuln/health`
- `GET /api/vuln/ready`

能力服务：

- `POST /api/vuln/services/register`
- `POST /api/vuln/services/heartbeat/{service_id}`
- `DELETE /api/vuln/services/unregister/{service_id}`
- `GET /api/vuln/services`
- `GET /api/vuln/services/{service_id}`

Case 与工作台：

- `POST /api/vuln/cases`
- `GET /api/vuln/cases`
- `GET /api/vuln/cases/{case_id}`
- `GET /api/vuln/cases/{case_id}/timeline`
- `GET /api/vuln/cases/ops/dashboard/overview`
- `GET /api/vuln/cases/ops/manual-tasks`
- `POST /api/vuln/cases/{case_id}/manual-tasks`
- `POST /api/vuln/cases/{case_id}/manual-tasks/{task_id}/status`
- `POST /api/vuln/cases/{case_id}/stage-transition`
- `POST /api/vuln/cases/{case_id}/decisions`
- `POST /api/vuln/cases/{case_id}/actions/dispatch`
- `GET /api/vuln/cases/{case_id}/recommended-actions`
- `POST /api/vuln/cases/{case_id}/orchestrate/auto`

Action：

- `GET /api/vuln/actions/ops/queue`
- `POST /api/vuln/actions/{action_id}/callback`
- `POST /api/vuln/actions/{action_id}/control`
- `POST /api/vuln/actions/mock-dispatch/{case_id}`

## 运行与验证

本地建议使用 `conda sothoth` 环境校验：

```bash
conda run --no-capture-output -n sothoth pytest 13-secflow-service/image_build/secflow-platform-vuln/tests -q
npm -C 13-secflow-service/image_build/secflow-frontend run lint
npm -C 13-secflow-service/image_build/secflow-frontend run build
```

## 文档导航

- [系统架构设计](doc/ARCHITECTURE.md)
- [API 汇总](doc/API.md)
- [架构与 API 总览](doc/SYSTEM_SUMMARY.md)
- [测试方案](doc/TEST_PLAN.md)
