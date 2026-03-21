# SecFlow 漏洞生命周期编排引擎

## 服务简介

`secflow-platform-vuln` 是 SecFlow 平台中的漏洞生命周期编排引擎。它不直接执行漏洞分析、验证、POC/EXP 生成等具体能力，而是负责注册外部漏洞能力微服务、编排漏洞处理流程、汇聚结果、驱动阶段推进，并为人工介入和平台审计提供统一框架。

## 当前阶段

当前实现为第一期骨架版本，已包含：

- 漏洞 `Case` 基础模型
- 外部微服务注册与心跳
- 生命周期运行实例与阶段历史
- 外部 Action 回调结果接入
- 平台附件元数据模型
- 设计文档与基础 API

尚未实现：

- 真实的复杂调度策略
- 去重逻辑
- 高级人工任务工作流
- S3/对象存储后端
- 前端页面

## 核心定位

- 平台侧负责生命周期编排
- 能力服务通过注册接入平台
- 外部服务负责分析、验证、POC、EXP、仿真等能力执行
- 平台统一保存结果、附件、时间线、阶段状态

## 目录结构

```text
secflow-platform-vuln/
├── app/
│   ├── api/
│   ├── models/
│   ├── services/
│   ├── config.py
│   ├── exception.py
│   └── main.py
├── config.yaml
├── doc/
│   ├── API.md
│   └── ARCHITECTURE.md
├── Dockerfile
└── requirements.txt
```

## 启动方式

```bash
cd 13-secflow-service/image_build/secflow-platform-vuln
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m app.main
```

## 主要接口

- `GET /api/vuln/health`
- `GET /api/vuln/ready`
- `POST /api/vuln/services/register`
- `POST /api/vuln/services/heartbeat/{service_id}`
- `GET /api/vuln/services`
- `POST /api/vuln/cases`
- `GET /api/vuln/cases`
- `GET /api/vuln/cases/{case_id}`
- `GET /api/vuln/cases/{case_id}/timeline`
- `POST /api/vuln/actions/{action_id}/callback`

## 设计文档

- [架构设计](doc/ARCHITECTURE.md)
- [API 设计](doc/API.md)
