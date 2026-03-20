# SecFlow 工作流状态管理服务架构文档

## 概述

SecFlow 工作流状态管理服务（secflow-platform-workflow-status）是一个独立的微服务，负责管理和查询工作流实例和任务的执行状态。

## 服务定位

本服务作为工作流系统的状态监控和查询中心，主要职责包括：

1. **状态查询**: 提供工作流实例和任务状态的查询接口
2. **状态历史**: 记录和查询状态变更历史
3. **统计分析**: 提供状态统计和概览信息
4. **日志查询**: 提供任务执行日志的查询接口

## 架构设计

### 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend / Gateway                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              secflow-platform-workflow-status                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    API Layer                         │   │
│  │    (workflow_status.py - REST API Endpoints)        │   │
│  └─────────────────────────────────────────────────────┘   │
│                              │                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  Service Layer                       │   │
│  │    (workflow_client.py - Business Logic)            │   │
│  │    (auth.py - Authentication)                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                              │                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  Data Layer                          │   │
│  │    (database.py - SQLAlchemy Models)                │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
           ┌──────────────────┼──────────────────┐
           ▼                  ▼                  ▼
    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
    │   MySQL     │    │  Workflow   │    │    Auth     │
    │  Database   │    │   Service   │    │   Service   │
    └─────────────┘    └─────────────┘    └─────────────┘
```

### 目录结构

```
secflow-platform-workflow-status/
├── app/
│   ├── __init__.py           # 包初始化
│   ├── config.py             # 配置管理（Pydantic + YAML）
│   ├── exception.py          # 自定义异常
│   ├── main.py               # FastAPI 应用入口
│   ├── api/                  # API路由层
│   │   ├── __init__.py
│   │   └── workflow_status.py    # 状态管理API
│   ├── models/               # 数据模型层
│   │   ├── __init__.py
│   │   └── database.py       # SQLAlchemy 数据库模型
│   ├── schemas/              # 数据验证模式
│   │   ├── __init__.py
│   │   └── schemas.py        # Pydantic 模式定义
│   └── services/             # 业务服务层
│       ├── __init__.py
│       ├── auth.py           # 认证服务客户端
│       └── workflow_client.py # Workflow服务客户端
├── doc/
│   ├── API.md                # API文档
│   └── ARCHITECTURE.md       # 架构文档
├── config.yaml               # 配置文件
├── Dockerfile                # Docker构建文件
├── requirements.txt          # Python依赖
└── start.py                  # 启动脚本
```

## 数据模型

### 核心实体

#### WorkflowInstanceStatus（工作流实例状态）

| 字段 | 类型 | 说明 |
|------|------|------|
| id | String(64) | 主键 |
| instance_id | String(64) | 实例ID（索引） |
| project_id | String(32) | 项目ID（索引） |
| workflow_name | String(128) | 工作流名称 |
| status | String(32) | 状态 |
| started_at | DateTime | 开始时间 |
| finished_at | DateTime | 结束时间 |
| duration_seconds | Integer | 执行时长（秒） |
| message | Text | 状态消息 |
| metadata | JSON | 元数据 |
| created_at | DateTime | 创建时间 |
| updated_at | DateTime | 更新时间 |

#### TaskStatus（任务状态）

| 字段 | 类型 | 说明 |
|------|------|------|
| id | String(64) | 主键 |
| task_id | String(64) | 任务ID（索引） |
| instance_id | String(64) | 实例ID（索引） |
| project_id | String(32) | 项目ID（索引） |
| task_name | String(128) | 任务名称 |
| status | String(32) | 状态 |
| started_at | DateTime | 开始时间 |
| finished_at | DateTime | 结束时间 |
| duration_seconds | Integer | 执行时长（秒） |
| message | Text | 状态消息 |
| metadata | JSON | 元数据 |
| created_at | DateTime | 创建时间 |
| updated_at | DateTime | 更新时间 |

#### StatusHistory（状态变更历史）

| 字段 | 类型 | 说明 |
|------|------|------|
| id | Integer | 主键（自增） |
| resource_type | String(32) | 资源类型（instance/task） |
| resource_id | String(64) | 资源ID（索引） |
| project_id | String(32) | 项目ID（索引） |
| from_status | String(32) | 原状态 |
| to_status | String(32) | 新状态 |
| reason | Text | 变更原因 |
| operator | String(64) | 操作者 |
| created_at | DateTime | 创建时间 |

## 服务依赖

### 内部服务

- **secflow-platform-auth**: 认证服务，用于Token验证
- **secflow-platform-workflow**: 工作流服务，用于获取实时状态和日志

### 外部依赖

- **MySQL**: 数据库，存储状态信息
- **Menu服务**: 服务注册中心（可选）

## 配置说明

### 数据库配置

```yaml
database:
  host: "172.31.30.100"
  port: 3306
  username: "secflow"
  password: "xxx"
  name: "secflow"
  table_prefix: "secflow_workflow_status_"
  pool_size: 10
  max_overflow: 20
```

### 认证配置

```yaml
auth_service:
  enabled: true
  host: "192.168.12.44"
  port: 10000
  validate_token_path: "/api/auth/validate-human-token"
  timeout: 10
  token_cache_enabled: true
  token_cache_ttl_minutes: 15
```

### Workflow服务配置

```yaml
workflow_service:
  host: "172.31.30.100"
  port: 10006
  timeout: 30
```

## API设计原则

### RESTful设计

- 遵循RESTful API设计规范
- 使用名词表示资源，动词表示操作
- 合理使用HTTP状态码

### 响应格式

**成功响应**:
```json
{
  "message": "操作成功",
  "data": { ... }
}
```

**错误响应**:
```json
{
  "code": "ERROR_CODE",
  "message": "错误信息",
  "details": { ... }
}
```

### 分页查询

使用 `page` 和 `page_size` 参数进行分页查询：

```
GET /api/workflow-status/instances?project_id=xxx&page=1&page_size=20
```

## 部署说明

### Docker部署

```bash
# 构建镜像
docker build -t secflow-platform-workflow-status:latest .

# 运行容器
docker run -d \
  --name workflow-status \
  -p 10007:10007 \
  -v /path/to/config.yaml:/app/config.yaml \
  secflow-platform-workflow-status:latest
```

### Kubernetes部署

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secflow-platform-workflow-status
spec:
  replicas: 2
  selector:
    matchLabels:
      app: workflow-status
  template:
    metadata:
      labels:
        app: workflow-status
    spec:
      containers:
      - name: workflow-status
        image: secflow-platform-workflow-status:latest
        ports:
        - containerPort: 10007
        livenessProbe:
          httpGet:
            path: /api/workflow-status/health
            port: 10007
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/workflow-status/ready
            port: 10007
          initialDelaySeconds: 5
          periodSeconds: 5
```

## 监控与日志

### 健康检查

- `/api/workflow-status/health`: 服务健康检查
- `/api/workflow-status/ready`: 服务就绪检查

### 日志格式

```
%(asctime)s - %(name)s - %(levelname)s - %(message)s
```

## 扩展性

### 添加新的状态类型

1. 在 `schemas.py` 中添加新的状态常量
2. 在 `database.py` 中更新状态验证
3. 在 `workflow_client.py` 中添加相应处理逻辑

### 添加新的查询接口

1. 在 `schemas.py` 中定义请求/响应模式
2. 在 `workflow_status.py` 中添加API路由
3. 在 `workflow_client.py` 中实现业务逻辑

## 安全考虑

1. **认证**: 所有API（除健康检查外）需要Token认证
2. **授权**: 基于项目ID的数据隔离
3. **输入验证**: 使用Pydantic进行参数验证
4. **SQL注入防护**: 使用SQLAlchemy ORM