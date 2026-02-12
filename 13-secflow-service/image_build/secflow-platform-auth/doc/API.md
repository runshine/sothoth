# SecFlow-User 用户认证微服务

## 1. 项目概述

### 1.1 简介

SecFlow-User 是一个基于 FastAPI 构建的用户认证微服务，提供完整的用户管理、角色管理和 Token 认证功能。主要用于机机之间和服务与用户之间的身份认证与授权。

### 1.2 功能特性

| 功能 | 说明 |
|------|------|
| 用户管理 | 支持用户的增、删、查、改 |
| 角色管理 | 支持创建角色、删除角色、查询角色 |
| 用户角色绑定 | 支持一个用户绑定一个或多个角色 |
| 机机Token认证 | 用于服务间调用的长期Token认证 |
| 人机Token认证 | 用于用户身份验证的短期Token认证 |
| Token验证API | 提供外部服务调用的Token验证接口 |
| 数据持久化 | 支持MySQL数据库 |

### 1.3 技术栈

- **Web框架**: FastAPI + Uvicorn
- **数据库**: MySQL + SQLAlchemy
- **认证**: JWT + BCrypt
- **运行环境**: Python 3.11

## 2. API 汇总

### 2.1 接口总览表

| 序号 | 分类 | 方法 | 接口路径 | 描述 | 认证要求 |
|:---:|:---|:---:|:---|:---|:---|
| 1 | 认证接口 | POST | `/api/auth/login` | 用户登录，获取人机Token | 无需认证 |
| 2 | 认证接口 | POST | `/api/auth/machine-token` | 申请机机Token | 无需认证 |
| 3 | 认证接口 | POST | `/api/auth/validate-human-token` | 验证人机Token有效性 | 无需认证 |
| 4 | 认证接口 | POST | `/api/auth/validate-machine-token` | 验证机机Token有效性 | 无需认证 |
| 5 | 认证接口 | GET | `/api/auth/machine-tokens` | 获取所有机机Token列表 | 机机Token |
| 6 | 认证接口 | DELETE | `/api/auth/machine-tokens/{token_id}` | 删除指定机机Token | 机机Token |
| 7 | 用户接口 | GET | `/api/auth/users/user_list` | 获取用户列表 | 机机Token |
| 8 | 用户接口 | POST | `/api/auth/users` | 创建新用户 | 机机Token |
| 9 | 用户接口 | GET | `/api/auth/users/{user_id}` | 获取单个用户详情 | 机机Token |
| 10 | 用户接口 | PUT | `/api/auth/users/{user_id}` | 更新用户信息 | 机机Token |
| 11 | 用户接口 | DELETE | `/api/auth/users/{user_id}` | 删除用户 | 机机Token |
| 12 | 用户接口 | GET | `/api/auth/users/{user_id}/role` | 获取用户角色 | 机机Token |
| 13 | 用户接口 | PUT | `/api/auth/users/{user_id}/role` | 覆盖绑定用户角色 | 机机Token |
| 14 | 用户接口 | POST | `/api/auth/users/{user_id}/role/add` | 增量添加用户角色 | 机机Token |
| 15 | 用户接口 | DELETE | `/api/auth/users/{user_id}/role` | 移除用户角色 | 机机Token |
| 16 | 用户接口 | POST | `/api/auth/users/{user_id}/password` | 修改指定用户密码 | 机机Token |
| 17 | 用户接口 | POST | `/api/auth/users/password/self` | 当前用户修改自己的密码 | 人机Token |
| 18 | 用户接口 | GET | `/api/auth/users/sessions/online` | 获取在线用户列表 | 机机Token |
| 19 | 用户接口 | GET | `/api/auth/users/{user_id}/sessions` | 获取指定用户的会话列表 | 机机Token |
| 20 | 用户接口 | DELETE | `/api/auth/users/{user_id}/sessions` | 撤销用户所有会话（踢下线） | 机机Token |
| 21 | 角色接口 | GET | `/api/auth/role_list` | 获取角色列表 | 机机Token |
| 22 | 角色接口 | POST | `/api/auth/role` | 创建新角色 | 机机Token |
| 23 | 角色接口 | GET | `/api/auth/role/{role_id}` | 获取单个角色详情 | 机机Token |
| 24 | 角色接口 | PUT | `/api/auth/role/{role_id}` | 更新角色信息 | 机机Token |
| 25 | 角色接口 | DELETE | `/api/auth/role/{role_id}` | 删除角色 | 机机Token |
| 26 | 机机Token管理 | GET | `/api/auth/machine-tokens` | 获取机机Token列表 | 机机Token |
| 27 | 机机Token管理 | GET | `/api/auth/machine-tokens/{token_id}` | 获取机机Token详情 | 机机Token |
| 28 | 机机Token管理 | POST | `/api/auth/machine-tokens` | 创建机机Token | 机机Token |
| 29 | 机机Token管理 | PUT | `/api/auth/machine-tokens/{token_id}` | 更新机机Token | 机机Token |
| 30 | 机机Token管理 | DELETE | `/api/auth/machine-tokens/{token_id}` | 删除机机Token | 机机Token |
| 31 | 机机Token管理 | POST | `/api/auth/machine-tokens/{token_id}/enable` | 启用机机Token | 机机Token |
| 32 | 机机Token管理 | POST | `/api/auth/machine-tokens/{token_id}/disable` | 禁用机机Token | 机机Token |
| 33 | 机机Token管理 | POST | `/api/auth/machine-tokens/{token_id}/regenerate` | 重新生成机机Token | 机机Token |
| 34 | 健康检查 | GET | `/api/auth/health` | 服务健康检查 | 无需认证 |

### 2.2 接口分类统计

| 分类 | 接口数量 | 说明 |
|:---|:---:|:---|
| 认证接口 | 6个 | 登录、Token申请与验证 |
| 用户接口 | 9个 | 用户CRUD及角色绑定管理 |
| 角色接口 | 5个 | 角色CRUD管理 |
| 机机Token管理 | 8个 | 机机Token的增删查改、启用/禁用、重新生成 |
| 健康检查 | 1个 | 服务状态检查 |

## 3. 快速开始

### 2.1 环境要求

- Python 3.11+
- MySQL 8.0+

### 2.2 安装依赖

```bash
# 安装Python依赖
pip install -r requirements.txt

# 安装MySQL驱动
pip install pymysql cryptography
```

### 2.3 配置环境变量

```bash
export DB_HOST=localhost
export DB_PORT=3306
export DB_NAME=secflow_user
export DB_USER=secflow_user
export DB_PASSWORD=your_password
export SECRET_KEY=your-secret-key-change-in-production
```

### 2.4 启动服务

```bash
# 开发模式启动
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload

# 生产模式启动
uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers 4
```

### 2.5 Docker启动

```bash
# 构建镜像
docker build -t secflow-user .

# 运行容器
docker run -d -p 8080:8080 \
  -e DB_HOST=mysql-host \
  -e DB_PORT=3306 \
  -e DB_NAME=secflow_user \
  -e DB_USER=secflow_user \
  -e DB_PASSWORD=password \
  --name secflow-user secflow-user
```

### 2.6 Docker Compose启动

```bash
docker-compose up -d
```

## 3. API接口文档

### 3.1 认证接口

#### 3.1.1 用户登录

**接口**: `POST /api/auth/login`

**说明**: 通过用户名密码换取人机Token

**请求参数**:
```json
{
  "username": "admin",
  "password": "password123"
}
```

**响应参数**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 86400
}
```

**错误响应**:
```json
{
  "detail": "用户名或密码错误"
}
```

---

#### 3.1.2 申请机机Token

**接口**: `POST /api/auth/machine-token`

**说明**: 通过机器码换取机机Token，用于服务间调用

**请求参数**:
```json
{
  "machine_code": "server-001",
  "description": "API Server"
}
```

**响应参数**:
```json
{
  "id": 1,
  "machine_code": "server-001",
  "description": "API Server",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00",
  "expires_at": null
}
```

---

#### 3.1.3 验证人机Token

    **接口**: `POST /api/auth/validate-human-token`

**说明**: 外部服务验证用户Token的有效性

**请求头**:
```
Authorization: Bearer <human_token>
```

**响应成功**:
```json
{
  "id": 1,
  "username": "admin",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00",
  "updated_at": "2024-01-01T00:00:00",
  "role": ["admin"]
}
```

**响应失败 (401)**:
```json
{
  "detail": "Token无效或已过期"
}
```

---

#### 3.1.4 验证机机Token

**接口**: `POST /api/auth/validate-machine-token`

**说明**: 外部服务验证机机Token的有效性

**请求头**:
```
Authorization: Bearer <machine_token>
```

**响应成功**:
```json
{
  "id": 1,
  "machine_code": "server-001",
  "description": "API Server",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00",
  "expires_at": null
}
```

**响应失败 (401)**:
```json
{
  "detail": "机机Token无效、已过期或已被禁用"
}
```

---

#### 3.1.5 获取机机Token列表

**接口**: `GET /api/auth/machine-tokens`

**说明**: 获取所有机机Token列表

**认证要求**: 需要机机Token

**响应**:
```json
[
  {
    "id": 1,
    "machine_code": "server-001",
    "description": "API Server",
    "is_active": true,
    "created_at": "2024-01-01T00:00:00",
    "expires_at": null
  }
]
```

---

#### 3.1.6 删除机机Token

**接口**: `DELETE /api/auth/machine-tokens/{token_id}`

**说明**: 删除指定的机机Token

**认证要求**: 需要机机Token

---

### 3.2 用户管理接口

#### 3.2.1 获取用户列表

**接口**: `GET /api/auth/users/user_list`

**认证要求**: 机机Token

**响应**:
```json
[
  {
    "id": 1,
    "username": "admin",
    "is_active": true,
    "created_at": "2024-01-01T00:00:00",
    "updated_at": "2024-01-01T00:00:00",
    "role": ["admin"]
  }
]
```

---

#### 3.2.2 创建用户

**接口**: `POST /api/auth/users`

**认证要求**: 机机Token

**请求参数**:
```json
{
  "username": "newuser",
  "password": "password123",
  "role_ids": [1, 2]
}
```

**响应**:
```json
{
  "id": 2,
  "username": "newuser",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00",
  "updated_at": "2024-01-01T00:00:00",
  "role": []
}
```

---

#### 3.2.3 获取单个用户

**接口**: `GET /api/auth/users/{user_id}`

**认证要求**: 机机Token

**响应**:
```json
{
  "id": 1,
  "username": "admin",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00",
  "updated_at": "2024-01-01T00:00:00",
  "role": ["admin"],
  "role_ids": [1]
}
```

---

#### 3.2.4 更新用户

**接口**: `PUT /api/auth/users/{user_id}`

**认证要求**: 机机Token

**请求参数**:
```json
{
  "username": "updated_user",
  "password": "new_password",
  "is_active": true
}
```

---

#### 3.2.5 删除用户

**接口**: `DELETE /api/auth/users/{user_id}`

**认证要求**: 机机Token

---

#### 3.2.6 获取用户角色

**接口**: `GET /api/auth/users/{user_id}/role`

**认证要求**: 机机Token

**响应**:
```json
{
  "user_id": 1,
  "role_ids": [1, 2],
  "role_names": ["admin", "user"]
}
```

---

#### 3.2.7 绑定用户角色

**接口**: `PUT /api/auth/users/{user_id}/role`

**认证要求**: 机机Token

**说明**: 覆盖模式绑定用户角色

**请求参数**:
```json
{
  "role_ids": [1, 2]
}
```

---

#### 3.2.8 添加用户角色

**接口**: `POST /api/auth/users/{user_id}/role/add`

**认证要求**: 机机Token

**说明**: 增量模式添加用户角色

**请求参数**:
```json
{
  "role_ids": [3]
}
```

---

#### 3.2.9 移除用户角色

**接口**: `DELETE /api/auth/users/{user_id}/role`

**认证要求**: 机机Token

**请求参数**:
```json
{
  "role_ids": [2]
}
```

---

#### 3.2.10 修改指定用户密码

**接口**: `POST /api/auth/users/{user_id}/password`

**认证要求**: 机机Token

**说明**: 管理员修改指定用户的密码，需要验证旧密码

**请求参数**:
```json
{
  "old_password": "current_password",
  "new_password": "new_password123"
}
```

**响应成功**:
```json
{
  "message": "密码已修改"
}
```

**错误响应**:
```json
{
  "detail": "旧密码错误"
}
```

---

#### 3.2.11 当前用户修改自己的密码

**接口**: `POST /api/auth/users/password/self`

**认证要求**: 人机Token

**说明**: 当前登录用户修改自己的密码

**请求头**:
```
Authorization: Bearer <human_token>
```

**请求参数**:
```json
{
  "old_password": "current_password",
  "new_password": "new_password123"
}
```

**响应成功**:
```json
{
  "message": "密码已修改"
}
```

**错误响应**:
```json
{
  "detail": "旧密码错误"
}
```

---

#### 3.2.12 获取在线用户列表

**接口**: `GET /api/auth/users/sessions/online`

**认证要求**: 机机Token

**说明**: 获取当前所有在线用户列表（登录状态为active且未过期的会话）

**响应成功**:
```json
[
  {
    "user_id": 1,
    "username": "admin",
    "role": ["admin"],
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0 ...",
    "login_at": "2024-01-01T00:00:00",
    "last_active_at": "2024-01-01T12:00:00"
  }
]
```

---

#### 3.2.13 获取指定用户的会话列表

**接口**: `GET /api/auth/users/{user_id}/sessions`

**认证要求**: 机机Token

**说明**: 获取指定用户的所有活跃和过期会话

**响应成功**:
```json
[
  {
    "id": 1,
    "token_jti": "550e8400-e29b-41d4-a716-446655440000",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0 ...",
    "status": "active",
    "created_at": "2024-01-01T00:00:00",
    "last_active_at": "2024-01-01T12:00:00",
    "expires_at": "2024-01-02T00:00:00"
  }
]
```

---

#### 3.2.14 撤销用户所有会话（踢下线）

**接口**: `DELETE /api/auth/users/{user_id}/sessions`

**认证要求**: 机机Token

**说明**: 将指定用户的所有活跃会话标记为revoked，使其Token失效

**响应成功**:
```json
{
  "message": "已撤销用户 admin 的所有会话"
}
```

---

### 3.3 角色管理接口

#### 3.3.1 获取角色列表

**接口**: `GET /api/auth/role_list`

**认证要求**: 机机Token

**响应**:
```json
[
  {
    "id": 1,
    "name": "admin",
    "description": "管理员角色",
    "created_at": "2024-01-01T00:00:00",
    "updated_at": "2024-01-01T00:00:00"
  }
]
```

---

#### 3.3.2 创建角色

**接口**: `POST /api/auth/role`

**认证要求**: 机机Token

**请求参数**:
```json
{
  "name": "editor",
  "description": "编辑角色"
}
```

---

#### 3.3.3 获取单个角色

**接口**: `GET /api/auth/role/{role_id}`

**认证要求**: 机机Token

**响应**:
```json
{
  "id": 1,
  "name": "admin",
  "description": "管理员角色",
  "created_at": "2024-01-01T00:00:00",
  "updated_at": "2024-01-01T00:00:00",
  "user_ids": [1]
}
```

---

#### 3.3.4 更新角色

**接口**: `PUT /api/auth/role/{role_id}`

**认证要求**: 机机Token

**请求参数**:
```json
{
  "name": "super_admin",
  "description": "超级管理员"
}
```

---

#### 3.3.5 删除角色

**接口**: `DELETE /api/auth/role/{role_id}`

**认证要求**: 机机Token

---

### 3.4 机机Token管理接口

#### 3.4.1 获取机机Token列表

**接口**: `GET /api/auth/machine-tokens`

**认证要求**: 机机Token

**响应**:
```json
[
  {
    "id": 1,
    "machine_code": "server-001",
    "description": "API Server",
    "is_active": true,
    "created_at": "2024-01-01T00:00:00",
    "expires_at": null
  }
]
```

---

#### 3.4.2 获取机机Token详情

**接口**: `GET /api/auth/machine-tokens/{token_id}`

**认证要求**: 机机Token

**响应**:
```json
{
  "id": 1,
  "token": "xAbC123...",
  "machine_code": "server-001",
  "description": "API Server",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00",
  "expires_at": null
}
```

---

#### 3.4.3 创建机机Token

**接口**: `POST /api/auth/machine-tokens`

**认证要求**: 机机Token

**请求参数**:
```json
{
  "machine_code": "server-002",
  "description": "New Server",
  "expires_at": "2025-12-31T23:59:59"
}
```

**响应**:
```json
{
  "id": 2,
  "token": "yZxW987...",
  "machine_code": "server-002",
  "description": "New Server",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00",
  "expires_at": "2025-12-31T23:59:59"
}
```

---

#### 3.4.4 更新机机Token

**接口**: `PUT /api/auth/machine-tokens/{token_id}`

**认证要求**: 机机Token

**请求参数**:
```json
{
  "description": "Updated Description",
  "expires_at": "2026-12-31T23:59:59"
}
```

---

#### 3.4.5 删除机机Token

**接口**: `DELETE /api/auth/machine-tokens/{token_id}`

**认证要求**: 机机Token

**响应成功**:
```json
{
  "message": "Token已删除"
}
```

---

#### 3.4.6 启用机机Token

**接口**: `POST /api/auth/machine-tokens/{token_id}/enable`

**认证要求**: 机机Token

**响应成功**:
```json
{
  "message": "Token已启用"
}
```

---

#### 3.4.7 禁用机机Token

**接口**: `POST /api/auth/machine-tokens/{token_id}/disable`

**认证要求**: 机机Token

**响应成功**:
```json
{
  "message": "Token已禁用"
}
```

---

#### 3.4.8 重新生成机机Token

**接口**: `POST /api/auth/machine-tokens/{token_id}/regenerate`

**认证要求**: 机机Token

**说明**: 为指定机器重新生成Token值，旧Token将失效

**响应**:
```json
{
  "id": 1,
  "token": "newTokenValue...",
  "machine_code": "server-001",
  "description": "API Server",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00",
  "expires_at": null
}
```

---

### 3.5 健康检查

**接口**: `GET /health`

**说明**: 服务健康检查

**响应**:
```json
{
  "status": "ok"
}
```

## 4. Token机制详解

### 4.1 人机Token（Human-to-Machine Token）

**用途**: 用户登录后获取，用于用户身份认证

**获取方式**: `POST /api/auth/login`

**特点**:
- JWT格式
- 有效期：24小时
- 包含用户ID、用户名、Token类型
- 存储在客户端

**Payload示例**:
```json
{
  "sub": "1",
  "username": "admin",
  "type": "human",
  "exp": 1704067200
}
```

### 4.2 机机Token（Machine-to-Machine Token）

**用途**: 服务间调用的身份认证

**获取方式**: `POST /api/auth/machine-token`

**特点**:
- 随机生成的Token字符串
- 存储在数据库中
- 可设置过期时间（可选）
- 可被禁用

## 5. 认证依赖使用

### 5.1 人机Token认证

```python
from fastapi import APIRouter, Depends
from app.dependencies import get_current_user

router = APIRouter()

@router.get("/protected")
def protected_route(user = Depends(get_current_user)):
    return {"user": user.username}
```

### 5.2 机机Token认证

```python
from fastapi import APIRouter, Depends
from app.dependencies import get_machine_client

router = APIRouter()

@router.get("/service-api")
def service_api(verified = Depends(get_machine_client)):
    return {"message": "Service verified"}
```

### 5.3 可选用户认证

```python
from fastapi import APIRouter, Depends
from app.dependencies import get_optional_user

router = APIRouter()

@router.get("/public-api")
def public_api(user = Depends(get_optional_user)):
    if user:
        return {"user": user.username}
    return {"user": "anonymous"}
```

## 6. 配置说明

配置文件路径：`config.yaml`

### 6.1 配置文件结构

```yaml
# 数据库配置（MySQL）
database:
  host: "localhost"
  port: 3306
  username: "secflow_user"
  password: "password"
  name: "secflow_user"
  charset: "utf8mb4"

# 应用配置
app:
  host: "0.0.0.0"
  port: 8080
  debug: false

# JWT配置
jwt:
  secret_key: "secflow-secret-key-change-in-production"
  algorithm: "HS256"
  access_token_expire_minutes: 1440  # 24小时
```

### 6.2 配置项说明

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| database.host | 数据库地址 | localhost |
| database.port | 数据库端口 | 3306 |
| database.username | 数据库用户名 | secflow_user |
| database.password | 数据库密码 | password |
| database.name | 数据库名 | secflow_user |
| database.charset | 字符集 | utf8mb4 |
| app.host | 监听地址 | 0.0.0.0 |
| app.port | 监听端口 | 8080 |
| app.debug | 调试模式 | false |
| jwt.secret_key | JWT密钥 | - |
| jwt.algorithm | JWT算法 | HS256 |
| jwt.access_token_expire_minutes | Token过期时间(分钟) | 1440 |

### 6.3 K8S配置

在K8S环境中，可以使用ConfigMap挂载配置文件：

### 6.2 数据库表结构

**users表**:
```sql
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

**roles表**:
```sql
CREATE TABLE role (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) UNIQUE NOT NULL,
    description VARCHAR(500),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

**user_roles关联表**:
```sql
CREATE TABLE user_roles (
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (role_id) REFERENCES role(id)
);
```

**machine_tokens表**:
```sql
CREATE TABLE machine_tokens (
    id INT PRIMARY KEY AUTO_INCREMENT,
    token VARCHAR(500) UNIQUE NOT NULL,
    machine_code VARCHAR(100) UNIQUE NOT NULL,
    description VARCHAR(500),
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at DATETIME NULL
);
```

## 7. K8S部署

命名空间：`sothothv2-ns`

### 7.1 部署ConfigMap

```bash
kubectl apply -f k8s-configmap.yaml -n sothothv2-ns
```

### 7.2 部署Deployment和Service

```bash
kubectl apply -f k8s-deployment.yaml -n sothothv2-ns
```

### 7.3 查看状态

```bash
# 查看Pod
kubectl get pods -n sothothv2-ns -l app=secflow-user

# 查看Service
kubectl get svc -n sothothv2-ns secflow-user

# 查看日志
kubectl logs -n sothothv2-ns -l app=secflow-user --tail=100
```

### 7.4 扩容

```bash
# 扩容到5个实例
kubectl scale deployment secflow-user -n sothothv2-ns --replicas=5

# 自动扩缩容（HPA）
kubectl autoscale deployment secflow-user -n sothothv2-ns \
  --min=3 --max=10 --cpu-percent=80
```

### 7.5 多实例部署说明

Deployment配置：
- 默认副本数：3
- 资源限制：CPU 100m-500m，内存 128Mi-256Mi
- 健康检查：liveness和readiness探针
- 配置挂载：通过ConfigMap挂载config.yaml

## 8. Docker Compose部署

### 8.1 完整配置

```yaml
version: '3.8'

services:
  secflow-user:
    image: secflow-user:latest
    container_name: secflow-user
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - DB_HOST=mysql-host
      - DB_PORT=3306
      - DB_NAME=secflow_user
      - DB_USER=secflow_user
      - DB_PASSWORD=your_password
      - SECRET_KEY=your-secret-key
    depends_on:
      - mysql-host
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  mysql-host:
    image: mysql:8.0
    container_name: mysql-host
    restart: unless-stopped
    environment:
      - MYSQL_ROOT_PASSWORD=root_password
      - MYSQL_DATABASE=secflow_user
      - MYSQL_USER=secflow_user
      - MYSQL_PASSWORD=your_password
    volumes:
      - mysql_data:/var/lib/mysql
    ports:
      - "3306:3306"

volumes:
  mysql_data:
```

### 8.2 启动命令

```bash
# 启动
docker-compose up -d

# 停止
docker-compose down

# 查看日志
docker-compose logs -f
```

## 9. 项目结构

```
secflow_user/
├── app/
│   ├── __init__.py
│   ├── main.py           # FastAPI入口
│   ├── database.py       # 数据库配置
│   ├── model.py          # SQLAlchemy模型
│   ├── schema.py         # Pydantic模式
│   ├── auth.py           # 认证工具
│   ├── dependencies.py   # 认证依赖
│   └── router/
│       ├── __init__.py
│       ├── auth.py       # 认证路由
│       ├── users.py      # 用户路由
│       └── roles.py      # 角色路由
├── doc/
│   └── API.md            # API文档
├── Dockerfile
├── docker-compose.yml
├── k8s-deployment.yaml
├── k8s-secret.yaml
├── requirements.txt
└── README.md
```

## 10. 常见问题

### Q1: 如何生成机机Token？

```bash
curl -X POST http://localhost:8080/api/auth/machine-token \
  -H "Content-Type: application/json" \
  -d '{"machine_code": "server-001", "description": "API Server"}'
```

### Q2: 如何验证用户Token是否有效？

```bash
curl -X POST http://localhost:8080/api/auth/validate-human-token \
  -H "Authorization: Bearer <token>"
```

### Q3: 如何设置Token过期时间？

机机Token支持通过`expires_at`字段设置过期时间（ISO 8601格式）：
```json
{
  "machine_code": "server-001",
  "description": "API Server",
  "expires_at": "2025-12-31T23:59:59"
}
```

### Q4: 数据库连接失败怎么办？

1. 检查MySQL服务是否运行
2. 检查数据库用户名密码是否正确
3. 检查数据库是否已创建
4. 检查网络连接是否正常

### Q5: 如何禁用某个Token？

通过删除机机Token来实现：
```bash
curl -X DELETE http://localhost:8080/api/auth/machine-tokens/1
```