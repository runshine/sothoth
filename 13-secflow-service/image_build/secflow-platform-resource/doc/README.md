# Secflow Resource Management Service

## 概述

Secflow Resource Management Service (资源管理服务) 是一个用于管理项目资源的微服务，支持软件测试项目五类资源的上传、解压和管理：

- **document**: 文档资源（PDF、Word、Markdown等）
- **software**: 软件包资源（压缩包、二进制文件等）
- **code**: 代码资源（源代码、脚本等）
- **other**: 其他资源
- **output_pvc**: 输出PVC资源（用于任务输出存储，不需要上传文件）

核心功能：
- 每次上传创建独立PVC，异步下载并解压压缩包
- 资源可关联到多个项目
- 提供任务查询、删除操作
- 任务失败后自动清理资源防止泄露

---

## 系统架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Secflow Resource Management                   │
├─────────────────────────────────────────────────────────────────────────┤
│  API Layer                                                           │
│  ├── GET  /api/resource                     - 服务信息              │
│  ├── POST /api/resource/resources/upload     - 上传资源（异步）    │
│  ├── GET  /api/resource/resources              - 资源列表          │
│  ├── GET  /api/resource/resources/{id}         - 资源详情          │
│  ├── GET  /api/resource/resources/{uuid}/file - 下载资源文件       │
│  ├── DELETE /api/resource/resources/{id}      - 删除资源          │
│  ├── GET  /api/resource/tasks/{task_id}        - 任务详情          │
│  ├── GET  /api/resource/tasks/{task_id}/logs   - 任务日志          │
│  ├── GET  /api/resource/tasks                  - 任务列表          │
│  ├── DELETE /api/resource/tasks/{task_id}     - 删除任务          │
│  ├── GET  /api/resource/pvcs                  - PVC列表            │
│  ├── POST /api/resource/output-pvc            - 创建输出PVC       │
│  ├── GET  /api/resource/output-pvc/{id}       - 输出PVC详情       │
│  ├── DELETE /api/resource/output-pvc/{id}     - 删除输出PVC       │
│  ├── GET  /api/resource/health               - 健康检查          │
│  ├── GET  /api/resource/ready               - 就绪检查           │
│  └── GET  /api/resource/uploads/{uuid}     - 静态文件服务（Job下载）│
└─────────────────────────────────────────────────────────────────────────┘
```
│  Services                                                            │
│  ├── UploadService    - 本地文件上传/下载服务                       │
│  ├── AuthService      - Token认证服务（调用auth-service）          │
│  ├── ProjectService  - 项目验证服务（调用secflow_project）        │
│  ├── K8sService      - Kubernetes操作服务                          │
│  │   ├── Namespace管理                                             │
│  │   ├── PVC生命周期管理（创建/删除）                             │
│  │   └── Job管理（下载/解压）                                     │
│  └── TaskManager     - 异步任务管理器                              │
│      ├── 任务创建/启动/状态管理                                    │
│      ├── 进度跟踪与日志                                           │
│      └── 失败清理机制                                             │
├─────────────────────────────────────────────────────────────────────────┤
│  Database                                                            │
│  ├── secflow_resource_project_association - 项目资源关联表        │
│  ├── secflow_resource_resource           - 资源表                 │
│  └── secflow_resource_async_task_log     - 异步任务日志表         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 文件上传流程

```
┌──────────┐     ┌──────────────────────┐     ┌───────────────────┐     ┌──────────────┐
│  前端     │────▶ │  secflow-resource    │────▶ │  K8S Job         │────▶ │  PVC        │
│          │     │  (临时存储)           │     │  (下载+解压)      │     │  (持久存储) │
└──────────┘     └──────────────────────┘     └───────────────────┘     └──────────────┘
                      │
                      │ /uploads/{uuid}
                      │ (静态文件服务)
                      ▼
                Job 通过此 URL 下载文件
```

1. 前端通过 `multipart/form-data` 上传文件到本服务
2. 文件保存到 `upload_dir` 目录
3. 创建异步任务，生成 archive_url: `{download_base_url}/uploads/{resource_uuid}`
4. K8S Job 从本服务的 `/uploads/{uuid}` 端点下载文件
5. Job 将文件解压到 PVC 根目录 `/`
6. 本服务充当静态文件服务器，供 K8S Job 下载文件

---

## 快速开始

### 1. 配置说明

编辑 `config.yaml` 文件：

```yaml
# 数据库配置
database:
  host: "172.31.30.100"
  port: 3306
  username: "secflow"
  password: "Huawei12#$"
  name: "secflow"
  pool_size: 10
  max_overflow: 20

# 应用配置
app:
  host: "0.0.0.0"
  port: 10002
  debug: false

# 认证服务配置（Auth微服务）
auth_service:
  base_url: "http://192.168.12.44:10000"
  validate_token_path: "/api/auth/validate-human-token"
  timeout: 10

# 项目服务配置（Secflow Project微服务）
project_service:
  base_url: "http://192.168.12.44:10001"
  get_project_path: "/api/project"
  timeout: 10

# Kubernetes配置
k8s:
  connection_mode: "kubeconfig"           # 或 "incluster"
  kubeconfig_path: "/home/runshine/.kube/config"
  storage_class_name: "nfs-storage-192.168.13.66"
  pvc_size: 10                            # PVC大小(Gi)
  job_timeout: 600                        # Job超时(秒)

# 异步任务配置
task:
  log_dir: "/tmp/task_log"
  max_concurrent_tasks: 10
  check_interval: 5

# 服务注册配置
registry:
  enabled: true
  menu_service_url: "http://192.168.12.44:10003"
  service_id: "secflow-resource"
  service_name: "资源管理服务"
```

### 2. Docker构建

```bash
cd /path/to/secflow_resource
docker build -t secflow-resource:latest .
```

### 3. Docker运行

```bash
docker run -d \
  --name secflow-resource \
  -p 10002:10002 \
  -v /home/runshine/.kube/config:/app/config/kubeconfig:ro \
  -e CONFIG_PATH=/app/config/config.yaml \
  secflow-resource:latest
```

---

## API文档

### 0. 服务信息

```http
GET /api/resource
```

**响应：**

```json
{
  "service": "secflow-resource-management",
  "version": "2.2.0",
  "description": "项目管理五类资源（文档、软件、代码、其他、输出PVC）的异步上传和解压服务",
  "endpoints": {
    "info": "GET /api/resource",
    "health": "GET /api/resource/health",
    "ready": "GET /api/resource/ready",
    "upload": "POST /api/resource/resources/upload",
    "resources": "GET /api/resource/resources",
    "resource_detail": "GET /api/resource/resources/{id}",
    "download_file": "GET /api/resource/resources/{uuid}/file",
    "delete_resource": "DELETE /api/resource/resources/{id}",
    "tasks": "GET /api/resource/tasks",
    "task_detail": "GET /api/resource/tasks/{task_id}",
    "task_logs": "GET /api/resource/tasks/{task_id}/logs",
    "delete_task": "DELETE /api/resource/tasks/{task_id}",
    "pvcs": "GET /api/resource/pvcs",
    "create_output_pvc": "POST /api/resource/output-pvc",
    "get_output_pvc": "GET /api/resource/output-pvc/{id}",
    "delete_output_pvc": "DELETE /api/resource/output-pvc/{id}",
    "job_download": "GET /api/resource/uploads/{uuid}"
  }
}
```

**注意：** 此端点不需要认证

---

### 认证

所有API请求都需要在Header中携带Token：

```
Authorization: Bearer <your_token>
```

**Token Payload:**

| 字段 | 类型 | 说明 |
|------|------|------|
| id | string | 用户ID |
| username | string | 用户名（可选） |
| type | string | 用户类型：human/robot |

---

### 1. 资源管理

#### 1.1 上传资源（异步任务）

```http
POST /api/resource/resources/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data

file=@package.zip
name=package-v1.0
resource_type=software
project_ids=proj-001,proj-002
pvc_size=10
```

**请求参数（multipart/form-data）：**

| 字段 | 类型 | 位置 | 必需 | 说明 |
|------|------|------|------|------|
| file | File | body | 是 | 上传的压缩包文件 |
| name | string | form | 是 | 资源名称 |
| resource_type | string | form | 是 | 资源类型：document/software/code/other/output_pvc |
| project_ids | string | form | 是 | 关联的项目ID列表（逗号分隔） |
| pvc_size | integer | form | 否 | PVC大小（Gi），默认10Gi |

**响应：**

```json
{
  "task_id": "task_abc123def456",
  "resource_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "message": "Resource upload task created successfully"
}
```

**处理流程：**
1. 文件上传到本服务的 `upload_dir` 目录
2. 生成 archive_url: `{download_base_url}/api/resource/uploads/{resource_uuid}`
3. 创建异步任务 → 创建 PVC → 创建 Job → Job 从本服务下载并解压到 PVC
4. 资源关联到所有指定的项目

**注意：** 压缩包会自动解压到PVC根目录 `/`

---

#### 1.2 资源列表

```http
GET /api/resource/resources?project_id=proj-001
Authorization: Bearer <token>

// 可选参数：
// - resource_type: document | software | code | other
// - upload_status: pending | running | completed | failed
```

**响应：**

```json
{
  "resources": [
    {
      "id": 1,
      "resource_uuid": "550e8400-e29b-41d4-a716-446655440000",
      "name": "package-v1.0",
      "resource_type": "software",
      "original_file_name": "package.zip",
      "original_file_size": 10485760,
      "original_file_md5": "d41d8cd98f00b204e9800998ecf8427e",
      "original_file_format": "zip",
      "upload_status": "completed",
      "upload_message": "Task completed successfully",
      "pvc_name": "secflow-pvc-550e8400e29b",
      "pvc_namespace": "secflow_proj-001",
      "pvc_size": 10,
      "extract_path": "/",
      "project_ids": ["proj-001", "proj-002"],
      "created_by": "user-001",
      "created_at": "2024-01-15T10:30:00",
      "updated_at": "2024-01-15T10:35:00"
    }
  ],
  "total": 1
}
```

---

#### 1.3 资源详情

```http
GET /api/resource/resources/{resource_id}
Authorization: Bearer <token>
```

---

#### 1.4 删除资源

```http
DELETE /api/resource/resources/{resource_id}
Authorization: Bearer <token>
```

**响应：**

```json
{
  "message": "Resource 1 deleted successfully",
  "deleted_pvc": "secflow-pvc-550e8400e29b"
}
```

---

#### 1.5 下载资源文件

```http
GET /api/resource/resources/{resource_uuid}/file
Authorization: Bearer <token>
```

**用途：** 供前端或其他服务下载已上传的原始文件

**响应：** 文件流（Octet-Stream）

---

#### 1.6 静态文件服务（供K8S Job下载）

```http
GET /api/resource/uploads/{resource_uuid}
```

**用途：** 供 K8S Job 下载上传的文件（Job 通过此 URL 下载压缩包）

**说明：**
- 此端点不需要认证（Job 在集群内访问）
- 返回原始上传文件（不是解压后的内容）
- 文件名使用数据库中记录的 `original_file_name`

---

### 2. 任务管理

#### 2.1 任务详情

```http
GET /api/resource/tasks/{task_id}
Authorization: Bearer <token>
```

**响应：**

```json
{
  "task_id": "task_abc123def456",
  "task_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "resource_id": 1,
  "project_id": "proj-001",
  "task_type": "upload_extract",
  "status": "succeeded",
  "progress": 100,
  "message": "Task completed successfully",
  "error_message": null,
  "input_params": {
    "resource_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "project_ids": ["proj-001", "proj-002"],
    "resource_name": "package-v1.0",
    "resource_type": "software",
    "archive_url": "http://secflow-resource-service:10002/api/resource/uploads/550e8400e29b41d4a716446655440000",
    "pvc_size": 10,
    "extract_path": "/",
    "original_file_name": "package.zip",
    "original_file_size": 10485760,
    "original_file_md5": null,
    "original_file_format": "zip"
  },
  "result": {
    "pvc_name": "secflow-pvc-550e8400e29b",
    "pvc_namespace": "secflow_proj-001",
    "pvc_size": 10,
    "extract_path": "/",
    "status": "completed"
  },
  "created_k8s_resource": [
    {"type": "pvc", "name": "secflow-pvc-550e8400e29b", "namespace": "secflow_proj-001"},
    {"type": "job", "name": "secflow-upload-550e8400e29b", "namespace": "secflow_proj-001"}
  ],
  "started_at": "2024-01-15T10:30:00",
  "finished_at": "2024-01-15T10:35:00",
  "created_at": "2024-01-15T10:30:00",
  "updated_at": "2024-01-15T10:35:00"
}
```

**字段说明：**

| 字段 | 类型 | 说明 |
|------|------|------|
| task_id | string | 任务唯一标识 |
| task_uuid | string | 任务UUID |
| resource_id | int | 关联的资源ID |
| project_id | string | 主项目ID（用于权限验证） |
| project_ids | array | 关联的所有项目ID列表 |
| task_type | string | 任务类型：upload_extract |
| status | string | 任务状态 |
| progress | int | 进度百分比(0-100) |
| message | string | 状态消息 |
| error_message | string | 错误信息（失败时） |
| input_params | object | 输入参数 |
| result | object | 执行结果 |
| created_k8s_resource | array | 创建的K8S资源列表 |

---

#### 2.2 任务日志

```http
GET /api/resource/tasks/{task_id}/logs
Authorization: Bearer <token>
```

**响应：**

```json
{
  "task_id": "task_abc123def456",
  "logs": [
    "2024-01-15 10:30:00 - Task created",
    "2024-01-15 10:30:01 - Creating PVC: secflow-pvc-550e8400e29b",
    "2024-01-15 10:30:05 - PVC created successfully",
    "2024-01-15 10:30:06 - Creating upload job: secflow-upload-550e8400e29b",
    "2024-01-15 10:31:00 - Job started",
    "2024-01-15 10:35:00 - Job completed successfully"
  ]
}
```

---

#### 2.3 任务列表

```http
GET /api/resource/tasks?project_id=proj-001
Authorization: Bearer <token>

// 可选参数：
// - task_type: upload_extract
// - status: pending | running | succeeded | failed | cancelled
```

**响应：**

```json
{
  "tasks": [
    {
      "task_id": "task_abc123def456",
      "resource_id": 1,
      "project_id": "proj-001",
      "task_type": "upload_extract",
      "status": "succeeded",
      "progress": 100,
      "message": "Task completed successfully",
      "created_at": "2024-01-15T10:30:00",
      "updated_at": "2024-01-15T10:35:00"
    }
  ],
  "total": 1
}
```

---

#### 2.4 删除任务

```http
DELETE /api/resource/tasks/{task_id}
Authorization: Bearer <token>
```

如果任务正在运行，会取消任务。

**响应：**

```json
{
  "message": "Task task_abc123def456 deleted successfully"
}
```

---

### 3. PVC管理

#### 3.1 PVC列表

查询指定项目的全部PVC资源。

```http
GET /api/resource/pvcs?project_id=proj-001
Authorization: Bearer <token>
```

**请求参数：**

| 字段 | 类型 | 位置 | 必需 | 说明 |
|------|------|------|------|------|
| project_id | string | query | 是 | 项目ID |

**响应：**

```json
{
  "pvcs": [
    {
      "pvc_name": "secflow-pvc-550e8400e29b",
      "namespace": "secflow-proj-001",
      "capacity": "10Gi",
      "status": "Bound",
      "storage_class": "nfs-client",
      "resource_id": 1,
      "resource_name": "package-v1.0",
      "resource_type": "software"
    },
    {
      "pvc_name": "secflow-pvc-abc123def456",
      "namespace": "secflow-proj-001",
      "capacity": "50Gi",
      "status": "Bound",
      "storage_class": "nfs-client",
      "resource_id": 2,
      "resource_name": "task-output-storage",
      "resource_type": "output_pvc"
    }
  ],
  "total": 2
}
```

**响应字段说明：**

| 字段 | 类型 | 说明 |
|------|------|------|
| pvc_name | string | PVC名称 |
| namespace | string | PVC所在命名空间 |
| capacity | string | PVC容量 |
| status | string | PVC状态（Bound/Pending/Lost等） |
| storage_class | string | 存储类名称 |
| resource_id | int | 关联的资源ID（如有） |
| resource_name | string | 关联的资源名称（如有） |
| resource_type | string | 关联的资源类型（如有） |

**说明：**
- 返回项目K8S命名空间中的所有PVC
- 如果PVC关联到本服务管理的资源，会返回资源信息
- 支持五类资源类型：document/software/code/other/output_pvc

---

### 4. 输出PVC管理

输出PVC是一种特殊资源类型（`output_pvc`），用于为任务提供输出存储空间。
与常规资源不同，输出PVC不需要上传文件，只需要指定大小即可创建。

#### 4.1 创建输出PVC

```http
POST /api/resource/output-pvc
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "task-output-storage",
  "description": "用于存储任务输出结果",
  "project_id": "proj-001",
  "pvc_size": 50
}
```

**请求参数：**

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| name | string | 是 | 输出PVC资源名称 |
| description | string | 否 | 资源描述 |
| project_id | string | 是 | 关联的项目ID |
| pvc_size | integer | 否 | PVC大小（Gi），默认10Gi，范围1-500 |

**响应（201）：**

```json
{
  "resource_id": 10,
  "resource_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "pvc_name": "secflow-pvc-550e8400e29b",
  "namespace": "secflow-proj-001",
  "capacity": "50Gi",
  "message": "Output PVC 'task-output-storage' created successfully"
}
```

**说明：**
- 创建后立即完成，不需要异步任务
- PVC名称自动生成，格式为 `secflow-pvc-{uuid[:12]}`
- `pvc_size` 单位是Gi，范围1-500

---

#### 4.2 获取输出PVC详情

```http
GET /api/resource/output-pvc/{resource_id}
Authorization: Bearer <token>
```

**响应：**

```json
{
  "id": 10,
  "resource_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "name": "task-output-storage",
  "description": "用于存储任务输出结果",
  "resource_type": "output_pvc",
  "pvc_name": "secflow-pvc-550e8400e29b",
  "pvc_namespace": "secflow-proj-001",
  "pvc_size": "50Gi",
  "status": "completed",
  "project_ids": ["proj-001"],
  "pvc_k8s_status": {
    "name": "secflow-pvc-550e8400e29b",
    "capacity": "50Gi",
    "status": "Bound",
    "storage_class": "nfs-client",
    "namespace": "secflow-proj-001"
  },
  "in_use": false,
  "use_message": "PVC is not in use",
  "created_at": "2024-01-15T10:30:00",
  "updated_at": "2024-01-15T10:30:00"
}
```

**字段说明：**

| 字段 | 类型 | 说明 |
|------|------|------|
| in_use | boolean | PVC是否正在被使用 |
| use_message | string | PVC使用状态描述 |
| pvc_k8s_status | object | K8S中PVC的实际状态 |

---

#### 4.3 删除输出PVC

```http
DELETE /api/resource/output-pvc/{resource_id}
Authorization: Bearer <token>
```

**删除规则：**
- **未关联**（没有Pod挂载、没有Job使用）：允许删除
- **已关联**（正在使用）：返回409错误，禁止删除

**响应（成功）：**

```json
{
  "message": "Output PVC resource 10 deleted successfully",
  "deleted_pvc": "secflow-pvc-550e8400e29b"
}
```

**响应（PVC在使用中，409）：**

```json
{
  "detail": "Cannot delete output PVC: PVC is mounted by running pod my-task-pod"
}
```

**响应（PVC在使用中，其他场景）：**

```json
{
  "detail": "Cannot delete output PVC: PVC is being used by active job my-task-job"
}
```

---

### 5. 健康检查

#### 5.1 健康检查

```http
GET /api/resource/health
```

**响应：**

```json
{
  "status": "healthy",
  "service": "secflow-resource-management",
  "version": "2.2.0",
  "dependencies": {
    "kubernetes": "healthy",
    "database": "healthy"
  }
}
```

---

#### 5.2 就绪检查

```http
GET /api/resource/ready
```

**响应：**

```json
{
  "status": "ready"
}
```

**503响应：**

```json
{
  "status": "not_ready",
  "reason": "Kubernetes not connected"
}
```

---

## 数据库表结构

### secflow_resource_project_association 表（项目资源关联表）

资源与项目的多对多关联表：

| 字段 | 类型 | 说明 |
|------|------|------|
| resource_id | INT | 资源ID，外键 |
| project_id | VARCHAR(64) | 项目ID，外键 |

### secflow_resource_resource 表（资源表）

| 字段 | 类型 | 说明 |
|------|------|------|
| id | INT | 主键 |
| resource_uuid | VARCHAR(36) | 资源UUID |
| name | VARCHAR(255) | 资源名称 |
| description | TEXT | 描述 |
| resource_type | ENUM | 资源类型 |
| projects | relationship | 关联的项目列表（多对多） |
| original_file_name | VARCHAR(255) | 原始文件名 |
| original_file_size | BIGINT | 文件大小 |
| original_file_md5 | VARCHAR(32) | 文件MD5 |
| original_file_format | VARCHAR(32) | 文件格式 |
| upload_status | ENUM | 上传状态 |
| upload_message | TEXT | 上传消息 |
| pvc_name | VARCHAR(255) | PVC名称 |
| pvc_namespace | VARCHAR(255) | PVC命名空间 |
| pvc_size | VARCHAR(16) | PVC大小 |
| extract_path | VARCHAR(1024) | 解压路径 |
| resource_metadata | JSON | 元数据 |
| created_by | VARCHAR(64) | 创建者 |
| created_at | DATETIME | 创建时间 |
| updated_at | DATETIME | 更新时间 |

**API返回格式说明：**

| 字段 | 类型 | 说明 |
|------|------|------|
| project_ids | array[string] | 关联的项目ID列表（从关联表查询） |

### secflow_resource_async_task_log 表（任务日志表）

| 字段 | 类型 | 说明 |
|------|------|------|
| id | INT | 主键 |
| task_id | VARCHAR(64) | 任务唯一标识 |
| task_uuid | VARCHAR(36) | 任务UUID |
| resource_id | INT | 关联资源ID |
| project_id | VARCHAR(64) | 主项目ID（用于权限验证） |
| task_type | ENUM | 任务类型 |
| status | ENUM | 任务状态 |
| progress | INT | 进度百分比 |
| message | TEXT | 任务消息 |
| error_message | TEXT | 错误消息 |
| input_params | JSON | 输入参数（含 `project_ids` 数组） |
| result | JSON | 执行结果 |
| created_k8s_resource | JSON | 创建的K8S资源 |
| started_at | DATETIME | 开始时间 |
| finished_at | DATETIME | 完成时间 |
| created_at | DATETIME | 创建时间 |
| updated_at | DATETIME | 更新时间 |

**字段说明：**

| 字段 | 类型 | 说明 |
|------|------|------|
| project_id | string | 主项目ID，用于权限验证 |
| input_params.project_ids | array | 关联的所有项目ID列表 |

---

## 枚举值说明

### ResourceType（资源类型）

| 值 | 说明 |
|---|------|
| document | 文档资源 |
| software | 软件包资源 |
| code | 代码资源 |
| other | 其他资源 |
| output_pvc | 输出PVC资源（用于任务输出存储，无需上传文件） |

### TaskType（任务类型）

| 值 | 说明 |
|---|------|
| upload_extract | 上传并解压任务 |

### TaskStatus（任务状态）

| 值 | 说明 |
|---|------|
| pending | 等待执行 |
| running | 执行中 |
| succeeded | 执行成功 |
| failed | 执行失败 |
| cancelled | 已取消 |

### ResourceUploadStatus（上传状态）

| 值 | 说明 |
|---|------|
| pending | 等待上传 |
| running | 上传中 |
| completed | 上传完成 |
| failed | 上传失败 |

---

## K8S部署说明

### 1. Namespace结构

每个项目会创建一个独立的namespace：
- 命名格式：`secflow_{project_id}`
- 每次上传创建独立的PVC

### 2. PVC说明

每次上传都会创建独立的PVC：
- PVC命名格式：`secflow-pvc-{uuid[:12]}`
- 默认大小：10Gi（可配置）
- 存储类：nfs-storage（可配置）

### 3. Job说明

用于下载并解压压缩包的Job：
- Job命名格式：`secflow-upload-{uuid[:12]}`
- 完成后5分钟自动清理
- 失败时自动清理创建的PVC

---

## 与Secflow Project的集成

本服务不管理项目，只通过调用 secflow_project 服务来验证项目访问权限：

- 资源操作前，先调用 secflow_project 验证用户是否有权限访问该项目
- 项目不存在或用户无权访问时，返回 403 错误
- 项目信息从 secflow_project 服务获取，不在本地存储

配置示例：
```yaml
project_service:
  base_url: "http://secflow-project-service.secflow:8080"  # K8S集群内地址
  get_project_path: "/api/project"
```

---

## 启动验证

服务启动时执行以下验证：

1. **配置参数验证**: 检查所有必需的配置参数
2. **数据库连接测试**: 测试与数据库的连接，失败则错误退出
3. **Kubernetes连接测试**: 测试与K8S集群的连接，失败则错误退出

验证失败时将输出错误日志并以非零状态码退出。

---

## 目录结构

```
secflow_resource/
├── config.yaml              # 配置文件
├── requirements.txt         # Python依赖
├── Dockerfile              # Docker构建文件
├── start.py               # 启动脚本
├── API_DOCS.md            # API文档（Markdown格式）
├── doc/
│   └── README.md           # 本文档
└── app/
    ├── __init__.py
    ├── main.py              # FastAPI入口
    ├── api/
    │   ├── __init__.py
    │   └── resources.py     # 资源API（含任务、PVC）
    ├── model/
    │   ├── __init__.py
    │   └── database.py      # 数据库模型
    ├── schemas/
    │   ├── __init__.py
    │   └── schemas.py       # Pydantic模型
    ├── services/
    │   ├── __init__.py
    │   ├── auth.py          # 认证服务
    │   ├── project.py       # 项目验证服务
    │   ├── k8s.py           # K8S服务
    │   ├── upload.py        # 上传服务
    │   └── registry.py      # 服务注册
    └── tasks/
        ├── __init__.py
        ├── manager.py       # 任务管理器
        └── worker.py        # 任务处理器
```

---

## 错误响应

### 401 Unauthorized

```json
{
  "detail": "Missing Authorization header"
}
```

或

```json
{
  "detail": "Invalid or expired token"
}
```

### 403 Forbidden

```json
{
  "detail": "No permission to access this project"
}
```

### 404 Not Found

```json
{
  "detail": "Resource not found"
}
```

或

```json
{
  "detail": "Task not found"
}
```

### 500 Internal Server Error

```json
{
  "detail": "Internal server error message"
}
```

---

## 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| 1.0.0 | - | 初始版本，支持基础资源管理 |
| 1.1.0 | - | 移除项目管理，通过secflow_project验证项目访问权限 |
| 2.0.0 | 2024-01 | 重构支持四类资源管理，每次上传创建独立PVC，异步任务机制 |
| 2.1.0 | 2025-02-04 | 支持资源关联多个项目；修复archive_url参数缺失问题；添加静态文件服务供Job下载 |
| 2.2.0 | 2025-02-06 | 新增输出PVC资源类型（output_pvc），支持直接创建空PVC用于任务输出存储，提供PVC使用状态检查和删除保护机制 | |