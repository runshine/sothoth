# SecFlow Project Management Service API 文档

## API 汇总

所有API均以 `/api/project` 为前缀，包括服务健康检查。

| 序号 | 方法 | 接口路径 | 说明 |
|------|------|----------|------|
| 1 | POST | `/api/project` | 创建项目 |
| 2 | GET | `/api/project` | 查询项目列表 |
| 3 | GET | `/api/project/{project_id}` | 查询单个项目 |
| 4 | PUT | `/api/project/{project_id}` | 修改项目 |
| 5 | DELETE | `/api/project/{project_id}` | 删除项目 |
| 6 | POST | `/api/project/{project_id}/role` | 绑定项目角色 |
| 7 | DELETE | `/api/project/{project_id}/role` | 解除项目角色绑定 |
| 8 | GET | `/api/project/{project_id}/namespace` | 获取项目Namespace状态 |
| 9 | GET | `/api/project/{project_id}/resources` | 获取项目K8S资源列表 |
| 10 | GET | `/api/project/{project_id}/pods/{pod_name}/logs` | 获取Pod日志 |
| 11 | DELETE | `/api/project/{project_id}/pods/{pod_name}` | 删除Pod |
| 12 | DELETE | `/api/project/{project_id}/pvcs/{pvc_name}` | 删除PVC |
| 13 | GET | `/api/project/health` | 服务健康检查 |
| 14 | GET | `/api/project/ready` | 服务就绪检查 |

## 概述

项目管理服务提供项目的创建、查询、修改、删除功能，并通过Token认证实现权限控制。每次请求都需要携带有效的Token到Auth服务进行验证。

## 认证

所有API请求都需要在Header中携带Token：

```
Authorization: Bearer <human_token>
```

### Token验证

服务会调用Auth服务验证Token有效性：

**接口**: `POST /api/auth/validate-human-token`

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

## 项目接口

### 1. 创建项目

**接口**: `POST /api/project`

**请求头**:
```
Authorization: Bearer <token>
Content-Type: application/json
```

**请求体**:
```json
{
  "name": "项目名称",
  "description": "项目描述（可选）",
  "k8s_namespace": "关联的K8S Namespace名称（可选）"
}
```

**响应** (201):
```json
{
  "id": "abcd1234efgh5678",
  "name": "项目名称",
  "description": "项目描述",
  "owner_id": "1",
  "owner_name": "admin",
  "k8s_namespace": "secflow-abcd1234efgh5678",
  "status": "active",
  "created_at": "2024-01-01T00:00:00",
  "updated_at": "2024-01-01T00:00:00",
  "roles": [
    {
      "user_id": "1",
      "role": "owner",
      "created_at": "2024-01-01T00:00:00"
    }
  ]
}
```

**说明**: 创建项目时会自动创建关联的K8S Namespace，namespace名称格式为 `secflow-{project_id}`

**错误响应**:
- 400: 参数验证错误
- 401: Token无效
- 409: 项目名称已存在

---

### 2. 查询项目列表

**接口**: `GET /api/project`

**请求头**:
```
Authorization: Bearer <token>
```

**响应** (200):
```json
{
  "total": 2,
  "projects": [
    {
      "id": "abcd1234efgh5678",
      "name": "项目名称",
      "description": "项目描述",
      "owner_id": "1",
      "owner_name": "admin",
      "k8s_namespace": "secflow-abcd1234efgh5678",
      "status": "active",
      "created_at": "2024-01-01T00:00:00",
      "updated_at": "2024-01-01T00:00:00",
      "roles": [...]
    }
  ]
}
```

---

### 3. 查询单个项目

**接口**: `GET /api/project/{project_id}`

**请求头**:
```
Authorization: Bearer <token>
```

**响应** (200):
```json
{
  "id": "abcd1234efgh5678",
  "name": "项目名称",
  "description": "项目描述",
  "owner_id": "1",
  "owner_name": "admin",
  "k8s_namespace": "secflow-abcd1234efgh5678",
  "status": "active",
  "created_at": "2024-01-01T00:00:00",
  "updated_at": "2024-01-01T00:00:00",
  "roles": [...]
}
```

**错误响应**:
- 401: Token无效
- 403: 无权访问此项目
- 404: 项目不存在

---

### 4. 修改项目

**接口**: `PUT /api/project/{project_id}`

**请求头**:
```
Authorization: Bearer <token>
Content-Type: application/json
```

**请求体**:
```json
{
  "name": "新项目名称（可选）",
  "description": "新项目描述（可选）",
  "k8s_namespace": "新的K8S Namespace名称（可选）"
}
```

**响应** (200): 返回修改后的项目信息

**错误响应**:
- 400: 参数验证错误
- 401: Token无效
- 403: 只有项目所有者可以修改
- 404: 项目不存在
- 409: 项目名称已存在

---

### 5. 删除项目

**接口**: `DELETE /api/project/{project_id}`

**请求头**:
```
Authorization: Bearer <token>
```

**说明**: 删除项目时会同时删除关联的K8S Namespace及所有资源

**响应** (200):
```json
{
  "message": "项目 abcd1234efgh5678 已删除"
}
```

**错误响应**:
- 401: Token无效
- 403: 只有项目所有者可以删除
- 404: 项目不存在

---

### 6. 绑定项目角色

**接口**: `POST /api/project/{project_id}/role`

**请求头**:
```
Authorization: Bearer <token>
Content-Type: application/json
```

**请求体**:
```json
{
  "user_id": "用户ID",
  "role": "角色 (owner/admin/member)"
}
```

**响应** (201):
```json
{
  "user_id": "1",
  "role": "admin",
  "created_at": "2024-01-01T00:00:00"
}
```

**错误响应**:
- 401: Token无效
- 403: 只有项目所有者可以绑定角色

---

### 7. 解除项目角色

**接口**: `DELETE /api/project/{project_id}/role?user_id={user_id}`

**请求头**:
```
Authorization: Bearer <token>
```

**响应** (200):
```json
{
  "message": "已解除用户 1 的角色绑定"
}
```

**说明**: 不能解除项目所有者的角色

---

### 8. 获取项目Namespace状态

**接口**: `GET /api/project/{project_id}/namespace`

**请求头**:
```
Authorization: Bearer <token>
```

**响应** (200):
```json
{
  "namespace": {
    "name": "secflow-abcd1234efgh5678",
    "status": "Active",
    "created_at": "2024-01-01T00:00:00Z"
  },
  "k8s_namespace": "secflow-abcd1234efgh5678"
}
```

---

### 9. 获取项目K8S资源列表

**接口**: `GET /api/project/{project_id}/resources`

**请求头**:
```
Authorization: Bearer <token>
```

**响应** (200):
```json
{
  "namespace": "secflow-abcd1234efgh5678",
  "pods": [
    {
      "name": "pod-name-xxx",
      "status": "Running",
      "ip": "10.244.0.10",
      "node": "worker-node-1"
    }
  ],
  "services": [
    {
      "name": "service-name",
      "type": "ClusterIP",
      "cluster_ip": "10.96.0.1",
      "ports": [80]
    }
  ],
  "configmaps": ["configmap-1", "configmap-2"],
  "secrets": ["secret-1"],
  "deployments": [
    {
      "name": "deployment-name",
      "replica": 3,
      "available_replica": 3,
      "ready_replica": 3
    }
  ],
  "statefulsets": [
    {
      "name": "statefulset-name",
      "replica": 1,
      "ready_replica": 1
    }
  ],
  "pvcs": [
    {
      "name": "pvc-name",
      "status": "Bound",
      "capacity": {"storage": "1Gi"},
      "storage_class": "standard"
    }
  ],
  "ingresses": [
    {
      "name": "ingress-name",
      "host": "example.com",
      "tls": ["example.com"]
    }
  ]
}
```

**说明**: 返回项目关联Namespace下的所有K8S资源信息

**错误响应**:
- 401: Token无效
- 403: 无权访问此项目
- 404: 项目不存在

---

### 10. 获取Pod日志

**接口**: `GET /api/project/{project_id}/pods/{pod_name}/logs`

**请求头**:
```
Authorization: Bearer <token>
```

**查询参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| tail_lines | int | 否 | 返回日志行数，默认100，最大10000 |
| container | string | 否 | 容器名称（多容器Pod时需要） |

**响应** (200):
```json
{
  "pod_name": "pod-name-xxx",
  "namespace": "secflow-abcd1234efgh5678",
  "logs": "2024-01-01 00:00:00 Starting application...\n2024-01-01 00:00:01 Application started successfully",
  "container": null
}
```

**说明**:
- 通过K8S API获取与项目关联的K8S Namespace下，指定名称的Pod的运行日志
- 支持设置返回行数 tail_lines，默认100行
- 多容器Pod可通过 container 参数指定容器

**错误响应**:
- 401: Token无效
- 403: 无权访问此项目
- 404: 项目或Pod不存在

---

### 11. 删除Pod

**接口**: `DELETE /api/project/{project_id}/pods/{pod_name}`

**请求头**:
```
Authorization: Bearer <token>
```

**说明**: 删除指定项目Namespace下的Pod

**响应** (200):
```json
{
  "message": "Pod pod-name-xxx 已删除"
}
```

**错误响应**:
- 401: Token无效
- 403: 无权访问此项目
- 404: 项目或Pod不存在
- 500: 删除失败

---

### 12. 删除PVC

**接口**: `DELETE /api/project/{project_id}/pvcs/{pvc_name}`

**请求头**:
```
Authorization: Bearer <token>
```

**说明**:
- 删除前会检查PVC是否被任何Pod使用
- 如PVC正在被使用，将返回409错误

**响应** (200):
```json
{
  "message": "PVC pvc-name 已删除"
}
```

**错误响应**:
- 401: Token无效
- 403: 无权访问此项目
- 404: 项目或PVC不存在
- 409: PVC正在被Pod使用

---

## 系统接口

### 健康检查

**接口**: `GET /api/project/health`

**响应**:
```json
{
  "status": "ok",
  "service": "secflow-project-service"
}
```

### 就绪检查

**接口**: `GET /api/project/ready`

**响应**:
```json
{
  "status": "ready"
}
```

---

## 错误码说明

| 错误码 | 说明 |
|--------|------|
| NOT_FOUND | 资源不存在 |
| FORBIDDEN | 无权限访问 |
| UNAUTHORIZED | 未认证 |
| VALIDATION_ERROR | 参数验证错误 |
| CONFLICT | 资源冲突 |
| INTERNAL_ERROR | 内部错误 |