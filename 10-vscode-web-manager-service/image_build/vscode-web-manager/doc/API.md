# VSCode Web Manager API Documentation

## Overview

| 项目 | 说明 |
|------|------|
| Service Name | Code Server Manager |
| Description | 提供Code Server实例的创建、销毁、重建、状态查询、日志查看等功能 |
| Version | 1.0.0 |
| Base Path | `/api/app/code-server` |
| Database | SQLite (异步) |

---

## API Endpoints Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| **POST** | `/projects/{project_id}/code-servers` | 创建Code Server实例 |
| **DELETE** | `/projects/{project_id}/code-servers` | 删除Code Server实例 |
| **POST** | `/projects/{project_id}/code-servers/restart` | 重建Code Server |
| **GET** | `/projects/{project_id}/code-servers` | 列出Code Server列表 |
| **GET** | `/projects/{project_id}/code-servers/{name}` | 获取单个Code Server详情 |
| **GET** | `/projects/{project_id}/code-servers/{name}/status` | 获取Code Server实时状态 |
| **GET** | `/projects/{project_id}/code-servers/{name}/logs` | 获取Pod日志 |
| **GET** | `/projects/{project_id}/tasks` | 列出任务列表 |
| **GET** | `/projects/{project_id}/tasks/{task_id}` | 获取任务详情 |
| **DELETE** | `/projects/{project_id}/tasks/{task_id}` | 删除任务 |

---

## API Details

### 1. Health Check

#### GET /health
健康检查端点。

**Response:**
```json
{
  "status": "healthy"
}
```

#### GET /ready
就绪检查端点。

**Response:**
```json
{
  "status": "ready"
}
```

---

### 2. Create Code Server

#### POST /projects/{project_id}/code-servers

创建Code Server实例。

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `project_id` | string | 项目ID |

**Request Body:**
```json
{
  "name": "my-vscode",
  "namespace": "default",
  "description": "My VSCode Server",
  "source_pvcs": [
    {
      "pvc_name": "source-pvc",
      "mount_path": "/home/project"
    }
  ],
  "output_pvcs": [
    {
      "pvc_name": "output-pvc",
      "mount_path": "/home/output",
      "storage_size": "1Gi"
    }
  ],
  "custom_env": {
    "KEY": "value"
  },
  "code_server_env": {
    "PASSWORD": "mypassword",
    "SUDO_PASSWORD": "sudopass",
    "PUID": 1000,
    "PGID": 1000,
    "TZ": "Asia/Shanghai"
  },
  "image": "registry.example.com/code-server:v1.0.0"
}
```

**Request Fields Description:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Code Server名称，1-64字符 |
| `namespace` | string | Yes | Kubernetes命名空间 |
| `description` | string | No | 描述信息 |
| `source_pvcs` | array | Yes | 源码PVC配置列表（必须存在） |
| `source_pvcs[].pvc_name` | string | Yes | PVC名称 |
| `source_pvcs[].mount_path` | string | Yes | 挂载路径 |
| `output_pvcs` | array | No | 输出PVC配置列表（不存在则创建） |
| `output_pvcs[].pvc_name` | string | No | PVC名称（可选，不指定则自动生成） |
| `output_pvcs[].mount_path` | string | Yes | 挂载路径 |
| `output_pvcs[].storage_size` | string | No | 存储大小（如1Gi） |
| `custom_env` | object | No | 自定义环境变量 |
| `code_server_env` | object | No | Code Server镜像环境变量（PASSWORD, SUDO_PASSWORD, PUID, PGID, TZ等） |
| `image` | string | No | 自定义code-server镜像地址，未指定则使用配置文件中的默认镜像 |

**Response (201 Created):**
```json
{
  "message": "Code Server创建任务已提交",
  "task_id": "abc123def456",
  "task_type": "create"
}
```

---

### 3. Delete Code Server

#### DELETE /projects/{project_id}/code-servers

删除Code Server实例。

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `project_id` | string | 项目ID |

**Request Body:**
```json
{
  "name": "my-vscode",
  "delete_output_pvcs": false
}
```

**Request Field Description:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Code Server名称 |
| `delete_output_pvcs` | boolean | No | 是否删除输出PVC，默认false |

**Response (202 Accepted):**
```json
{
  "message": "Code Server删除任务已提交",
  "task_id": "def456ghi789",
  "task_type": "delete"
}
```

---

### 4. Restart Code Server

#### POST /projects/{project_id}/code-servers/restart

重建Code Server实例（先删除后创建）。

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `project_id` | string | 项目ID |

**Request Body:**
```json
{
  "name": "my-vscode"
}
```

**Response (202 Accepted):**
```json
{
  "message": "Code Server重建任务已提交",
  "task_id": "ghi789jkl012",
  "task_type": "restart"
}
```

---

### 5. List Code Servers

#### GET /projects/{project_id}/code-servers

列出指定项目的所有Code Server实例。

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `project_id` | string | 项目ID |

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | 可选，按状态筛选 |

**Response (200 OK):**
```json
{
  "total": 1,
  "items": [
    {
      "id": "abc123def456",
      "project_id": "project-001",
      "name": "my-vscode",
      "namespace": "default",
      "status": "running",
      "source_pvcs": [
        {
          "pvc_name": "source-pvc",
          "mount_path": "/home/project"
        }
      ],
      "output_pvcs": [
        {
          "pvc_name": "output-pvc",
          "mount_path": "/home/output",
          "storage_size": "1Gi"
        }
      ],
      "deployment_name": "cs-my-vscode-deploy",
      "service_name": "cs-my-vscode-svc",
      "ingress_name": "cs-my-vscode-ing",
      "pod_name": "cs-my-vscode-pod-xxx",
      "access_url": "https://my-vscode.example.com",
      "code_server_env": {
        "PUID": 1000,
        "PGID": 1000,
        "TZ": "Asia/Shanghai",
        "PASSWORD": "******"
      },
      "description": "My VSCode Server",
      "created_at": "2024-01-01T00:00:00",
      "updated_at": "2024-01-01T00:00:00"
    }
  ]
}
```

**Status Values:**
| Status | Description |
|--------|-------------|
| `pending` | 等待执行 |
| `creating` | 创建中 |
| `running` | 运行中 |
| `stopped` | 已停止 |
| `error` | 错误 |
| `deleting` | 删除中 |
| `deleted` | 已删除 |

---

### 6. Get Code Server Detail

#### GET /projects/{project_id}/code-servers/{name}

获取单个Code Server实例的详细信息。

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `project_id` | string | 项目ID |
| `name` | string | Code Server名称 |

**Response (200 OK):**
```json
{
  "id": "abc123def456",
  "project_id": "project-001",
  "name": "my-vscode",
  "namespace": "default",
  "status": "running",
  "source_pvcs": [
    {
      "pvc_name": "source-pvc",
      "mount_path": "/home/project"
    }
  ],
  "output_pvcs": [
    {
      "pvc_name": "output-pvc",
      "mount_path": "/home/output",
      "storage_size": "1Gi"
    }
  ],
  "deployment_name": "cs-my-vscode-deploy",
  "service_name": "cs-my-vscode-svc",
  "ingress_name": "cs-my-vscode-ing",
  "pod_name": "cs-my-vscode-pod-xxx",
  "access_url": "https://my-vscode.example.com",
  "description": "My VSCode Server",
  "created_at": "2024-01-01T00:00:00",
  "updated_at": "2024-01-01T00:00:00"
}
```

---

### 7. Get Code Server Status

#### GET /projects/{project_id}/code-servers/{name}/status

获取Code Server实例的实时运行状态（从Kubernetes获取）。

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `project_id` | string | 项目ID |
| `name` | string | Code Server名称 |

**Response (200 OK):**
```json
{
  "id": "abc123def456",
  "name": "my-vscode",
  "namespace": "default",
  "status": "running",
  "pod_status": "Running",
  "pod_ip": "10.244.0.10",
  "node_name": "node-001",
  "access_url": "https://my-vscode.example.com",
  "ready_replica": 1,
  "total_replica": 1
}
```

---

### 8. Get Code Server Logs

#### GET /projects/{project_id}/code-servers/{name}/logs

获取Code Server Pod的日志。

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `project_id` | string | 项目ID |
| `name` | string | Code Server名称 |

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tail_lines` | integer | 100 | 返回最后N行日志 |
| `container` | string | code-server | 容器名称 |

**Response (200 OK):**
```json
{
  "code_server_id": "abc123def456",
  "code_server_name": "my-vscode",
  "namespace": "default",
  "pod_name": "cs-my-vscode-pod-xxx",
  "container": "code-server",
  "logs": "2024-01-01 00:00:00 | info | Listening on http://0.0.0.0:8080..."
}
```

---

### 9. List Tasks

#### GET /projects/{project_id}/tasks

列出指定项目的异步任务列表。

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `project_id` | string | 项目ID |

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | 可选，按状态筛选 |
| `type` | string | 可选，按类型筛选（create/delete/restart） |

**Response (200 OK):**
```json
{
  "total": 1,
  "items": [
    {
      "id": "abc123def456",
      "project_id": "project-001",
      "type": "create",
      "status": "completed",
      "code_server_id": "code-server-001",
      "code_server_name": "my-vscode",
      "params": {
        "name": "my-vscode",
        "namespace": "default"
      },
      "result": "Code Server创建成功",
      "error_message": null,
      "created_at": "2024-01-01T00:00:00",
      "started_at": "2024-01-01T00:00:01",
      "completed_at": "2024-01-01T00:00:05"
    }
  ]
}
```

**Status Values:**
| Status | Description |
|--------|-------------|
| `pending` | 等待执行 |
| `running` | 执行中 |
| `completed` | 已完成 |
| `failed` | 失败 |
| `cancelled` | 已取消 |

---

### 10. Get Task Detail

#### GET /projects/{project_id}/tasks/{task_id}

获取单个任务的详细信息。

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `project_id` | string | 项目ID |
| `task_id` | string | 任务ID |

**Response (200 OK):**
```json
{
  "id": "abc123def456",
  "project_id": "project-001",
  "type": "create",
  "status": "completed",
  "code_server_id": "code-server-001",
  "code_server_name": "my-vscode",
  "params": {
    "name": "my-vscode",
    "namespace": "default"
  },
  "result": "Code Server创建成功",
  "error_message": null,
  "created_at": "2024-01-01T00:00:00",
  "started_at": "2024-01-01T00:00:01",
  "completed_at": "2024-01-01T00:00:05"
}
```

---

### 11. Delete Task

#### DELETE /projects/{project_id}/tasks/{task_id}

删除已完成或失败的任务记录。

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `project_id` | string | 项目ID |
| `task_id` | string | 任务ID |

**Response (200 OK):**
```json
{
  "success": true
}
```

---

## Error Response

所有API在发生错误时返回统一的错误格式：

```json
{
  "error": "Not Found",
  "detail": "Code Server不存在: my-vscode"
}
```

**Common Error Types:**
| Error | HTTP Status | Description |
|-------|-------------|-------------|
| `Not Found` | 404 | 资源不存在 |
| `Validation Error` | 400 | 请求参数验证错误 |
| `Conflict` | 409 | 资源冲突（如名称已存在） |
| `Internal Server Error` | 500 | 内部错误 |

---

## Data Models

### CodeServer Entity

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | 主键，32位MD5哈希 |
| `project_id` | string | 关联项目ID |
| `name` | string | 实例名称 |
| `namespace` | string | Kubernetes命名空间 |
| `status` | string | 实例状态 |
| `source_pvcs` | JSON | 源码PVC配置列表 |
| `output_pvcs` | JSON | 输出PVC配置列表 |
| `deployment_name` | string | Kubernetes Deployment名称 |
| `service_name` | string | Kubernetes Service名称 |
| `ingress_name` | string | Kubernetes Ingress名称 |
| `pod_name` | string | Kubernetes Pod名称 |
| `access_url` | string | 访问URL |
| `code_server_env` | JSON | Code Server环境变量配置 |
| `description` | string | 描述信息 |
| `created_at` | datetime | 创建时间 |
| `updated_at` | datetime | 更新时间 |

### Task Entity

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | 主键，32位MD5哈希 |
| `project_id` | string | 关联项目ID |
| `type` | string | 任务类型（create/delete/restart） |
| `status` | string | 任务状态 |
| `code_server_id` | string | 关联Code Server ID |
| `code_server_name` | string | 关联Code Server名称 |
| `params` | JSON | 任务参数 |
| `result` | string | 执行结果 |
| `error_message` | string | 错误信息 |
| `created_at` | datetime | 创建时间 |
| `started_at` | datetime | 开始执行时间 |
| `completed_at` | datetime | 完成时间 |

---

## Dependencies

```text
fastapi==0.109.0
uvicorn[standard]==0.27.0
sqlalchemy==2.0.25
pymysql==1.1.0
pydantic==2.5.0
pydantic-settings==2.1.0
pyyaml==6.0.1
httpx==0.26.0
python-multipart==0.0.6
kubernetes==29.0.0
python-dotenv==1.0.0
cryptography==42.0.0
aiosqlite==0.19.0
```

---

## Configuration

服务通过 `config.yaml` 配置文件进行配置，主要配置项：

```yaml
database:
  path: "./webapi_server.db"

k8s:
  namespace_prefix: "code-server-"
  default_storage_class: ""
  default_container_image: "registry.example.com/code-server:latest"
  default_resources_limits:
    cpu: "2000m"
    memory: "2Gi"
  default_resource_requests:
    cpu: "100m"
    memory: "128Mi"
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Client (Frontend/API)                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   FastAPI Application                        │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                     API Routes                            ││
│  │  - /project/{id}/code-servers (CRUD)                    ││
│  │  - /project/{id}/code-servers/{name}/status             ││
│  │  - /project/{id}/code-servers/{name}/logs               ││
│  │  - /project/{id}/tasks (CRUD)                           ││
│  └─────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────┐│
│  │                   Services                               ││
│  │  - TaskManager (异步任务执行器)                        ││
│  │  - KubernetesClient (K8S资源管理)                     ││
│  └─────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────┐│
│  │                   Database (SQLite)                     ││
│  │  - CodeServer Table                                    ││
│  │  - Task Table                                         ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Kubernetes Cluster                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                   │
│  │ Namespace │ │   PVC    │ │  Pod    │                   │
│  └──────────┘ └──────────┘ └──────────┘                   │
│  ┌──────────┐ ┌──────────┐                                 │
│  │ Deployment │ │ Service │                                 │
│  └──────────┘ └──────────┘                                 │
│  ┌──────────┐                                              │
│  │ Ingress  │                                              │
│  └──────────┘                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Usage Guide

### 1. 快速开始

#### 1.1 环境准备

确保Kubernetes集群可用，并配置好kubectl访问凭证：

```bash
# 验证Kubernetes连接
kubectl cluster-info

# 创建项目命名空间
kubectl create namespace my-project
```

#### 1.2 准备PVC

创建源码存储卷：

```bash
kubectl create -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: source-pvc
  namespace: my-project
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
EOF
```

#### 1.3 启动服务

```bash
# 方式一：直接运行
cd /path/to/vscode-web-manager
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload

# 方式二：Docker运行
docker run -d \
  --name vscode-web-manager \
  -p 8080:8080 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -v $(pwd)/data:/app/data \
  vscode-web-manager:latest
```

---

### 2. 典型使用场景

#### 2.1 创建Code Server实例

```bash
curl -X POST "http://localhost:8080/api/app/code-server/projects/project-001/code-servers" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "dev-vscode",
    "namespace": "my-project",
    "description": "开发环境VSCode",
    "source_pvcs": [
      {
        "pvc_name": "source-pvc",
        "mount_path": "/workspace"
      }
    ],
    "output_pvcs": [
      {
        "pvc_name": "dev-output-pvc",
        "mount_path": "/output",
        "storage_size": "5Gi"
      }
    ],
    "custom_env": {
      "PYTHONPATH": "/workspace",
      "NODE_ENV": "development"
    }
  }'
```

**响应：**
```json
{
  "message": "Code Server创建任务已提交",
  "task_id": "a1b2c3d4e5f6",
  "task_type": "create"
}
```

#### 2.2 轮询任务状态

创建任务提交后，通过返回的task_id轮询任务状态：

```bash
# 查询任务状态
curl "http://localhost:8080/api/app/code-server/projects/project-001/tasks/a1b2c3d4e5f6"
```

**响应（任务执行中）：**
```json
{
  "id": "a1b2c3d4e5f6",
  "project_id": "project-001",
  "type": "create",
  "status": "running",
  "code_server_id": "cs-dev-vscode",
  "code_server_name": "dev-vscode",
  "params": {"name": "dev-vscode", "namespace": "my-project"},
  "result": null,
  "error_message": null,
  "created_at": "2024-01-01T10:00:00",
  "started_at": "2024-01-01T10:00:01",
  "completed_at": null
}
```

**响应（任务完成）：**
```json
{
  "id": "a1b2c3d4e5f6",
  "project_id": "project-001",
  "type": "create",
  "status": "completed",
  "code_server_id": "cs-dev-vscode",
  "code_server_name": "dev-vscode",
  "params": {"name": "dev-vscode", "namespace": "my-project"},
  "result": "Code Server创建成功",
  "error_message": null,
  "created_at": "2024-01-01T10:00:00",
  "started_at": "2024-01-01T10:00:01",
  "completed_at": "2024-01-01T10:00:15"
}
```

#### 2.3 获取访问地址

任务完成后，查询Code Server详情获取访问URL：

```bash
curl "http://localhost:8080/api/app/code-server/projects/project-001/code-servers/dev-vscode"
```

**响应：**
```json
{
  "id": "cs-dev-vscode",
  "project_id": "project-001",
  "name": "dev-vscode",
  "namespace": "my-project",
  "status": "running",
  "source_pvcs": [
    {
      "pvc_name": "source-pvc",
      "mount_path": "/workspace"
    }
  ],
  "output_pvcs": [],
  "deployment_name": "cs-dev-vscode-deploy",
  "service_name": "cs-dev-vscode-svc",
  "ingress_name": "cs-dev-vscode-ing",
  "pod_name": "cs-dev-vscode-deploy-abc123-xyz",
  "access_url": "https://dev-vscode.example.com",
  "description": "开发环境VSCode",
  "created_at": "2024-01-01T10:00:00",
  "updated_at": "2024-01-01T10:00:15"
}
```

#### 2.4 查看运行日志

```bash
# 查看最近100行日志
curl "http://localhost:8080/api/app/code-server/projects/project-001/code-servers/dev-vscode/logs"

# 查看最近20行日志
curl "http://localhost:8080/api/app/code-server/projects/project-001/code-servers/dev-vscode/logs?tail_lines=20"
```

#### 2.5 重启实例

```bash
curl -X POST "http://localhost:8080/api/app/code-server/projects/project-001/code-servers/restart" \
  -H "Content-Type: application/json" \
  -d '{"name": "dev-vscode"}'
```

#### 2.6 删除实例

```bash
curl -X DELETE "http://localhost:8080/api/app/code-server/projects/project-001/code-servers" \
  -H "Content-Type: application/json" \
  -d '{"name": "dev-vscode", "delete_output_pvcs": false}'
```

---

### 3. 完整工作流示例

```python
import httpx
import time

BASE_URL = "http://localhost:8080/api/app/code-server"
PROJECT_ID = "projects/project-001"

def create_and_wait(code_server_name: str, namespace: str, timeout: int = 300) -> dict:
    """创建Code Server并等待任务完成"""

    # 1. 创建Code Server
    create_response = httpx.post(
        f"{BASE_URL}/{PROJECT_ID}/code-servers",
        json={
            "name": code_server_name,
            "namespace": namespace,
            "source_pvcs": [{"pvc_name": "source-pvc", "mount_path": "/workspace"}],
            "output_pvcs": [{"pvc_name": f"{code_server_name}-output", "mount_path": "/output"}],
        }
    )
    task_id = create_response.json()["task_id"]

    # 2. 轮询任务状态
    start_time = time.time()
    while time.time() - start_time < timeout:
        task_response = httpx.get(f"{BASE_URL}/{PROJECT_ID}/tasks/{task_id}")
        task_data = task_response.json()

        if task_data["status"] == "completed":
            return task_data
        elif task_data["status"] == "failed":
            raise Exception(f"任务失败: {task_data.get('error_message')}")

        time.sleep(2)

    raise Exception("任务超时")

# 使用示例
try:
    result = create_and_wait("dev-vscode", "my-project")
    print(f"创建成功: {result['result']}")

    # 3. 获取访问地址
    detail = httpx.get(f"{BASE_URL}/{PROJECT_ID}/code-servers/dev-vscode").json()
    print(f"访问地址: {detail['access_url']}")

except Exception as e:
    print(f"错误: {e}")
```

---

### 4. 常见问题

#### Q1: 创建任务失败，提示"Namespace not found"
**解决方案**：确保指定的namespace已在创建，或使用已存在的namespace。

#### Q2: 任务状态一直是"running"，长时间没有变化
**解决方案**：
1. 检查Kubernetes集群状态
2. 查看服务日志：`kubectl logs -n <service-ns> <pod-name>`
3. 检查Pod状态：`kubectl get pods -n <namespace>`

#### Q3: PVC挂载失败
**解决方案**：
1. 确认PVC已创建且状态为Bound
2. 检查PVC和Pod是否在同一namespace
3. 验证存储类是否可用

#### Q4: 无法访问Web UI
**解决方案**：
1. 检查Ingress状态：`kubectl get ingress -n <namespace>`
2. 验证域名解析是否正确
3. 检查防火墙/负载均衡器配置

#### Q5: 如何自定义容器镜像
**解决方案**：在`config.yaml`中修改`k8s.default_container_image`配置项。

---

### 5. 最佳实践

1. **命名规范**
   - Code Server名称使用项目名称+环境后缀（如 `dev-vscode`、`prod-vscode`）
   - namespace与项目ID保持一致

2. **资源管理**
   - 根据团队规模合理配置资源限制
   - 定期清理不再使用的Code Server实例

3. **监控告警**
   - 监控任务失败率
   - 监控Pod重启次数
   - 设置资源使用率告警

4. **安全建议**
   - 使用TLS/HTTPS访问
   - 配置适当的RBAC权限
   - 定期更新容器镜像版本

---

### 6. Kubernetes资源清理

手动清理残留资源：

```bash
# 删除Deployment
kubectl delete deployment -n <namespace> cs-<name>-deploy

# 删除Service
kubectl delete service -n <namespace> cs-<name>-svc

# 删除Ingress
kubectl delete ingress -n <namespace> cs-<name>-ing

# 删除Pod
kubectl delete pod -n <namespace> cs-<name>-pod-xxx

# 删除PVC（会丢失数据）
kubectl delete pvc -n <namespace> <pvc-name>
```