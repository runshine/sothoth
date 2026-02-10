# SecFlow 项目管理服务

## 服务简介

SecFlow项目管理服务是一个基于Python的微服务，提供项目的创建、查询、删除、修改等功能，支持多实例部署，并集成了K8S namespace管理能力。

## 功能特性

- 项目CRUD操作
- 基于Token的用户认证（集成Auth微服务）
- 基于角色的访问控制
- K8S Namespace自动管理（创建/删除）
- MySQL数据库持久化
- 多实例部署支持

## 快速开始

### 1. 环境准备

```bash
# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 2. 配置修改

编辑 `config.yaml` 文件，修改以下配置项：

```yaml
# 数据库配置
database:
  host: "your_mysql_host"
  port: 3306
  username: "your_username"
  password: "your_password"
  name: "your_database"
  table_prefix: "secflow_project_"

# Auth微服务配置
auth_service:
  host: "auth-service.default.svc.cluster.local"
  port: 8080
  validate_token_path: "/api/auth/validate-human-token"

# Menu注册中心配置
registry:
  enabled: true
  menu_service_url: "http://secflow-menu-service.secflow.svc.cluster.local:5000"
  service_id: "secflow-project"
  service_name: "项目管理服务"
  host: "0.0.0.0"
  port: 8080
  maturity: "已上线"
  description: "提供项目的创建、查询、删除、修改等功能"
  api_prefix: "/api/project"
  menu:
    id: "project-manage"
    path: "/project"
    icon: "folder"
    order: 2
    level1:
      name: "系统管理"
      name_en: "System"
    level2:
      name: "用户管理"
      name_en: "User Management"
    level3:
      name: "项目管理"
      name_en: "Project Management"

# K8S配置
kubernetes:
  in_cluster: true  # K8S集群内运行
  # kubeconfig: "/path/to/kubeconfig"  # 集群外调试使用

# 应用配置
app:
  host: "0.0.0.0"
  port: 8080
  debug: false
```

### 3. 启动服务

```bash
python -m app.main
```

### 4. Docker部署

```bash
docker build -t secflow-project-service .
docker run -v /path/to/config.yaml:/app/config.yaml secflow-project-service
```

## API接口

### 认证

所有API请求都需要在Header中携带Token：

```
Authorization: Bearer <human_token>
```

### 项目接口

| 方法 | 路径 | 说明 | 权限 |
|------|------|------|------|
| POST | /api/project | 创建项目 | 需要认证 |
| GET | /api/project | 查询项目列表 | 需要认证 |
| GET | /api/project/{project_id} | 查询单个项目 | 需要认证 |
| PUT | /api/project/{project_id} | 修改项目 | 需要认证（项目所有者） |
| DELETE | /api/project/{project_id} | 删除项目 | 需要认证（项目所有者） |
| POST | /api/project/{project_id}/role | 绑定项目角色 | 需要认证（项目所有者） |
| DELETE | /api/project/{project_id}/role | 解除项目角色 | 需要认证（项目所有者） |
| GET | /api/project/{project_id}/namespace | 获取Namespace状态 | 需要认证 |

## 项目结构

```
secflow_project/
├── app/
│   ├── __init__.py
│   ├── main.py           # 应用入口
│   ├── config.py         # 配置加载
│   ├── model.py          # 数据库模型
│   ├── schemas.py        # Pydantic模式
│   ├── api/
│   │   ├── __init__.py
│   │   └── projects.py   # 项目API路由
│   ├── service/
│   │   ├── __init__.py
│   │   ├── auth.py       # 认证服务
│   │   ├── k8s.py        # K8S客户端
│   │   └── registry.py   # Menu注册中心服务
│   └── exception.py      # 异常定义
├── config.yaml           # 配置文件
├── requirements.txt      # Python依赖
├── Dockerfile            # Docker构建文件
└── doc/
    └── api.md           # API文档
```

## 数据库表结构

服务启动时会自动创建以下表：

- `secflow_project`: 项目表
- `secflow_project_role_bind`: 项目-角色关联表

## K8S集成

### 创建项目

创建项目时，自动创建 `secflow_{project_id}` 的namespace。

### 删除项目

删除项目时，自动删除该namespace下的所有资源。

## Menu注册中心集成

服务启动时自动向Menu注册中心注册，并定期发送心跳（默认30秒间隔）：

- **服务ID**: `secflow-project`
- **服务名称**: `项目管理服务`
- **菜单项**: `project-manage`（归属于 `user-manage`）

## License

MIT