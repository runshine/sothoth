# Sothoth Project Map

这份文档用于给后续开发和联调提供一个稳定的项目索引，减少重复探索成本。

## 1. 仓库整体定位

`sothoth` 是一个多服务安全平台仓库，根目录同时包含：

- 基础设施服务
- SecFlow 核心业务服务
- Agent / 外围应用镜像
- MCP 相关服务
- 少量本地开发与自动化工具

根目录可见的主要目录：

- `00-pre-init`: 预初始化资源，当前可见 `certs/`
- `01-mysql-service`: MySQL 服务
- `02-vpn-access-service`: VPN 访问服务
- `03-elk-service`: ELK 相关服务
- `06-nacos-registry-service`: Nacos 注册中心
- `09-redis-service`: Redis 服务
- `11-new-api-service`: 新 API 服务区
- `12-harbor-service`: Harbor 私有镜像仓库
- `13-secflow-service`: SecFlow 平台核心服务
- `14-sotothv1-service`: 旧版 Sothoth v1 服务
- `99-external-service`: 外部依赖服务
- `100-agent-service-image`: Agent 相关镜像
- `mcp_service`: MCP 服务
- `java_utils`: Java 工具

## 2. 根目录开发工具

- 根目录 [package.json](/home/runshine/CLionProjects/sothoth/package.json) 只声明了 `@playwright/test` 和 `@mermaid-js/mermaid-cli`
- 说明仓库根目录的 Node.js 主要用于测试/文档渲染，而不是主业务运行时
- 根目录 [README.md](/home/runshine/CLionProjects/sothoth/README.md) 很简短，当前更像部署引导而不是架构说明

## 3. 核心业务区

核心业务代码集中在：

- `13-secflow-service/00-secflow-06-00-platform-static-binary`
- `13-secflow-service/00-secflow-07-00-deploy-script`
- `13-secflow-service/image_build`

其中真正活跃、可直接开发的主要代码在 `13-secflow-service/image_build`。

## 4. image_build 服务地图

`13-secflow-service/image_build` 下目前识别到这些核心模块：

- `secflow-frontend`: React + Vite 前端
- `secflow-platform-auth`: 用户、角色、Token 认证服务
- `secflow-platform-project`: 项目管理服务
- `secflow-platform-menu`: 动态菜单与服务注册中心
- `secflow-platform-fileserver`: 文件服务
- `secflow-platform-resource`: 资源管理服务
- `secflow-platform-configcenter`: 配置中心，一期聚焦 LLM 渠道配置
- `secflow-platform-k8s`: K8S 资源管理服务
- `secflow-platform-workflow`: 工作流编排服务
- `secflow-platform-workflow-status`: 工作流状态与监控服务
- `secflow-platform-vuln`: 漏洞生命周期编排引擎
- `secflow-platform-deploy-script`: 部署脚本服务
- `secflow-platform-agent`: Agent 平台服务
- `secflow-platform-static-binary`: 静态二进制管理服务
- `secflow-app-code-server`: code-server 管理应用
- `secflow-app-secmate-ng`: secmate-ng 集成应用
- `secflow-platform-skill-shop`: 当前目录存在，但本轮未看到明确代码主体

## 5. 技术栈总览

### 前端

- `secflow-frontend` 使用 React 19 + TypeScript + Vite
- 入口文件是 [index.tsx](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-frontend/index.tsx)
- 开发配置在 [vite.config.ts](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-frontend/vite.config.ts)
- 默认开发端口 `3000`
- `/api` 代理到 `http://secflow.sothothv2.com`

### 后端

后端以 Python 微服务为主，分成两类：

- FastAPI + Uvicorn: 大多数平台服务
- Flask: 少数遗留或轻量服务

已确认使用 FastAPI 的模块：

- `secflow-platform-auth`
- `secflow-platform-configcenter`
- `secflow-platform-deploy-script`
- `secflow-platform-fileserver`
- `secflow-platform-k8s`
- `secflow-platform-project`
- `secflow-platform-resource`
- `secflow-platform-vuln`
- `secflow-platform-workflow`
- `secflow-platform-workflow-status`
- `secflow-app-code-server`
- `secflow-app-secmate-ng`

已确认使用 Flask 的模块：

- `secflow-platform-agent`
- `secflow-platform-menu`
- `secflow-platform-static-binary`

## 6. 前端结构速记

前端目录：

- [secflow-frontend](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-frontend)

关键子目录：

- `pages/`: 页面主集合，覆盖用户、项目、环境、工作流、漏洞、输入资源等
- `clients/`: 各后端服务 API 客户端封装
- `components/`: 通用组件
- `layout/`: 顶部栏、侧边栏
- `constants/`, `types/`, `utils/`: 常量、类型、工具
- `public/config.js`: 前端公开配置

从页面命名看，前端已覆盖的主要业务域包括：

- 用户与权限
- 组织与项目
- 资源/输入物管理
- 环境与 Agent 管理
- Workflow 模板、实例与日志
- LLM 配置中心与聊天工作台
- 漏洞引擎工作台
- code-server / 终端类能力

## 7. 主要服务职责速记

### 7.1 Auth

目录：

- [secflow-platform-auth](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-auth)

职责：

- 用户管理
- 角色管理
- 多角色绑定
- 机机 Token
- 人机 Token
- Token 校验

文档入口：

- [README.md](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-auth/README.md)
- [doc/API.md](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-auth/doc/API.md)

### 7.2 Project

目录：

- [secflow-platform-project](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-project)

职责：

- 项目 CRUD
- Auth 鉴权集成
- RBAC
- K8S namespace 自动管理
- 可向 Menu 服务注册自身

### 7.3 Menu

目录：

- [secflow-platform-menu](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-menu)

职责：

- 服务注册/注销
- 心跳检测
- 健康聚合检查
- 动态菜单生成
- Redis 共享状态

这是平台服务发现和前端菜单拼装的重要节点。

### 7.4 Fileserver

目录：

- [secflow-platform-fileserver](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-fileserver)

职责：

- 项目维度文件上传/下载/删除/移动/重命名
- 多 Pod 共享 RWX 存储
- 通过 auth/project 做鉴权和访问校验

### 7.5 Resource

目录：

- [secflow-platform-resource](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-resource)

从目录和文档命名判断，它是平台资源管理服务，和输入物、PVC、基础资源等能力关系很密切。

### 7.6 Config Center

目录：

- [secflow-platform-configcenter](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-configcenter)

职责：

- 平台级配置中心
- 当前重点为全局 LLM 渠道配置管理与消费接口

### 7.7 K8S

目录：

- [secflow-platform-k8s](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-k8s)

职责：

- K8S 资源管理
- WebSocket/资源操作类接口
- 很可能是环境、实例、容器、服务终端等能力的基础支撑层

### 7.8 Workflow

目录：

- [secflow-platform-workflow](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-workflow)
- [secflow-platform-workflow-status](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-workflow-status)

职责：

- Workflow 模板、Job 模板、App 模板
- Workflow 实例
- 终端代理
- 状态追踪、监控、生命周期事件

工作流相关能力在平台里是一个独立的大域。

### 7.9 Vuln

目录：

- [secflow-platform-vuln](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-vuln)

职责：

- 漏洞生命周期编排引擎
- 服务注册、Case 管理、Action 分发
- 结果回调、时间线、人工任务、裁决
- 前端工作台、K8S 部署、镜像构建链路已打通

这个模块是平台内相对完整、独立、文档也较丰富的一块。

### 7.10 Deploy Script

目录：

- [secflow-platform-deploy-script](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-deploy-script)

职责：

- 部署脚本管理与分发相关能力

### 7.11 Agent / Static Binary

目录：

- [secflow-platform-agent](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-agent)
- [secflow-platform-static-binary](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-static-binary)

这两个模块仍是平台重要拼图，但本轮只完成了技术栈确认，尚未做深入代码级职责拆解。

### 7.12 App 层

目录：

- [secflow-app-code-server](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-code-server)
- [secflow-app-secmate-ng](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-app-secmate-ng)

职责：

- 这类模块更像平台集成应用，不是纯平台基础服务
- `code-server` 模块用于在线 VSCode Web 实例创建、销毁、重建和日志管理
- `secmate-ng` 模块用于接入 secmate-ng 能力

## 8. 常见联调入口

### 前端

目录：

- [secflow-frontend](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-frontend)

已确认启动方式：

```bash
npm run dev
```

已确认开发地址：

- `http://127.0.0.1:3000/`

### Python 微服务

从项目结构看，多数模块都支持以下模式之一：

- `python app/main.py`
- `python app.py`
- `uvicorn app.main:app --host 0.0.0.0 --port <port>`
- `python start.py`

具体启动参数需要看各模块 `README.md`、`start.py`、`Dockerfile` 或 `config.yaml`。

## 9. 当前探索结论

- 这个仓库不是单体项目，而是“平台 + 基础设施 + 外围应用 + Agent + 运维服务”的大仓
- SecFlow 核心业务主要集中在 `13-secflow-service/image_build`
- 平台后端以 Python FastAPI 为主，辅以少量 Flask 服务
- 前端是一个较完整的单页应用，已经覆盖多个业务域
- `menu`、`auth`、`project`、`k8s`、`workflow`、`resource/fileserver` 之间很可能构成平台主干
- `vuln` 是一个业务边界非常清晰、实现也较完整的独立子系统

## 10. 后续推荐的深入顺序

如果后续要继续“免重探”开发，建议优先补齐下面几块的深度地图：

1. 前端 API 客户端到后端服务的映射关系
2. 各服务 `config.yaml` / 环境变量 / 默认端口
3. 服务间依赖链路图
4. 本地开发最小启动集
5. 数据库表与核心模型分布

## 11. 记忆说明

我不能保证跨会话永久记住这个仓库，但这份文档已经放进项目里，后续我可以直接基于它继续工作，而不必每次都从零开始扫目录。
