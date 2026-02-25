# SecFlow Workflow Service API Reference

## API 汇总

### API 列表

| 模块 | 方法 | 端点 | 描述 |
|------|------|------|------|
| **App Template** | POST | `/api/workflow/app-templates` | 创建应用模板 |
| | GET | `/api/workflow/app-templates` | 列表应用模板 |
| | GET | `/api/workflow/app-templates/{template_id}` | 获取应用模板详情 |
| | PUT | `/api/workflow/app-templates/{template_id}` | 更新应用模板 |
| | DELETE | `/api/workflow/app-templates/{template_id}` | 删除应用模板 |
| **Job Template** | POST | `/api/workflow/job-templates` | 创建任务模板 |
| | GET | `/api/workflow/job-templates` | 列表任务模板 |
| | GET | `/api/workflow/job-templates/{template_id}` | 获取任务模板详情 |
| | PUT | `/api/workflow/job-templates/{template_id}` | 更新任务模板 |
| | DELETE | `/api/workflow/job-templates/{template_id}` | 删除任务模板 |
| **Workflow Template** | POST | `/api/workflow/workflow-templates` | 创建工作流模板 |
| | GET | `/api/workflow/workflow-templates` | 列表工作流模板 |
| | GET | `/api/workflow/workflow-templates/{template_id}` | 获取工作流模板详情 |
| | PUT | `/api/workflow/workflow-templates/{template_id}` | 更新工作流模板 |
| | DELETE | `/api/workflow/workflow-templates/{template_id}` | 删除工作流模板 |
| **Workflow Instance** | POST | `/api/workflow/workflow-instances` | 创建工作流实例 |
| | GET | `/api/workflow/workflow-instances` | 列表工作流实例 |
| | GET | `/api/workflow/workflow-instances/{instance_id}` | 获取工作流实例详情 |
| | PUT | `/api/workflow/workflow-instances/{instance_id}` | 更新工作流实例 |
| | POST | `/api/workflow/workflow-instances/{instance_id}/start` | 启动工作流 |
| | POST | `/api/workflow/workflow-instances/{instance_id}/stop` | 停止工作流 |
| | POST | `/api/workflow/workflow-instances/{instance_id}/activate` | 激活持久化工作流 |
| | POST | `/api/workflow/workflow-instances/{instance_id}/deactivate` | 停用持久化工作流 |
| | DELETE | `/api/workflow/workflow-instances/{instance_id}` | 删除工作流实例 |
| | GET | `/api/workflow/workflow-instances/{instance_id}/status` | 获取实例状态 |
| | GET | `/api/workflow/workflow-instances/{instance_id}/nodes/{node_id}/logs` | 获取节点日志 |
| **Trigger** | POST | `/api/workflow/workflow-instances/triggers/{instance_id}` | HTTP触发工作流 |
| **Health** | GET | `/api/workflow/health` | 健康检查 |

### 通用参数

| 参数 | 类型 | 描述 |
|------|------|------|
| `template_id` | string | 模板ID |
| `instance_id` | string | 实例ID |
| `project_id` | string | 项目ID |
| `scope` | string | 模板范围: `global` 或 `project` |

### 状态枚举

| 状态 | 描述 |
|------|------|
| `pending` | 待执行 |
| `running` | 运行中 |
| `succeeded` | 成功 |
| `failed` | 失败 |
| `stopped` | 已停止 |

### 运行模式

| 模式 | 描述 |
|------|------|
| `once` | 一次性运行，工作流执行一次后结束 |
| `persistent` | 持久化运行，工作流持续有效，可被多次触发 |

### 触发器类型

| 类型 | 描述 |
|------|------|
| `manual` | 手动触发，仅可通过API启动 |
| `http` | HTTP触发，可通过HTTP请求触发工作流 |

---

## Overview

SecFlow Workflow Service 提供应用模板、任务模板和工作流编排管理。所有API前缀为 `/api/workflow`。

## Base URL

```
http://<host>:<port>/api/workflow
```

## Authentication

所有API需要在Authorization头中携带Bearer token:

```
Authorization: Bearer <token>
```

Token由认证服务验证。

---

## App Template API

管理持久化应用模板 (Deployment类型)。

### Create App Template

**POST** `/api/workflow/app-templates`

创建应用模板 (支持多容器)。

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | 模板名称 |
| description | string | No | 模板描述 |
| scope | string | No | `global` 或 `project`，默认: `project` |
| project_id | string | Required if scope=project | 项目ID |
| containers | array | Yes | 容器配置列表 (至少一个) |
| service_port | array | No | 服务端口配置 |
| service_name | string | No | K8s Service名称 (不指定则自动生成) |
| create_service | boolean | No | 是否创建K8s Service默认: true |
| service_type | string | No | Service类型: ClusterIP、LoadBalancer、NodePort |
| replicas | integer | No | 副本数，默认: 1 |

**Container Object:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | 容器名称 |
| image | string | Yes | 容器镜像 |
| command | array | No | 启动命令 |
| args | array | No | 命令参数 |
| env_vars | array | No | 固定环境变量 `[{"name": "KEY", "value": "VALUE"}]` |
| volume_mounts | array | No | 固定PVC挂载 (已知PVC) `[{"pvc_name": "pvc", "mount_path": "/data", "sub_path": "subdir", "read_only": false}]` |
| input_env_vars | array | No | 输入环境变量依赖 (仅声明name，source_node_id在实例化时指定) |
| input_volume_mounts | array | No | 输入挂载依赖 (仅声明mount_path，source_node_id在实例化时指定) |
| privileged | boolean | No | 特权模式，默认: false |
| image_pull_policy | string | No | `Always`, `IfNotPresent`, `Never` |
| resources | object | No | 资源要求 (requests最小资源, limits资源限制) |
| liveness_probe | object | No | 存活探针配置 |
| readiness_probe | object | No | 就绪探针配置 |

**VolumeMount Object (固定挂载):**

| Field | Type | Description |
|-------|------|-------------|
| pvc_name | string | PVC名称 (模板定义时已知) |
| mount_path | string | 容器内挂载路径 |
| sub_path | string | PVC子目录挂载 (可选) |
| read_only | boolean | 只读挂载 |

**ServicePort Object (模板级 - Service端口):**

| Field | Type | Description |
|-------|------|-------------|
| name | string | 端口名称 |
| port | integer | Service 端口 |
| target_port | integer | 容器目标端口 |
| protocol | string | 协议 (默认: TCP) |

> 注意: service_ports 在模板级别定义，用于创建 Kubernetes Service。

**EnvVarInput Object (输入环境变量 - 模板级):**

| Field | Type | Description |
|-------|------|-------------|
| name | string | 环境变量名 (在当前容器设置) |
| default_value | string | 默认值 |

**VolumeMountInput Object (输入挂载 - 模板级):**

| Field | Type | Description |
|-------|------|-------------|
| mount_path | string | 容器内需要挂载的路径 |
| sub_path | string | PVC子目录挂载 (可选) |
| read_only | boolean | 只读挂载 (默认true) |

> 注意: 输入依赖在模板中只声明需要的路径(name/mount_path)，具体的来源(source_node_id)需要在工作流模板节点配置时指定。

**ResourceRequirements Object:**

| Field | Type | Description |
|-------|------|-------------|
| requests | object | 最小资源请求 `{cpu: "100m", memory: "128Mi"}` |
| limits | object | 资源限制 `{cpu: "500m", memory: "512Mi"}` |

**Health Check Object:**

| Field | Type | Description |
|-------|------|-------------|
| type | string | `http`, `tcp`, 或 `exec` |
| port | integer | 健康检查端口 |
| path | string | HTTP健康检查路径 |
| command | array | Exec命令 |
| initial_delay_seconds | integer | 初始延迟 |
| period_seconds | integer | 检查周期 |
| timeout_seconds | integer | 超时时间 |
| failure_threshold | integer | 失败阈值 |
| success_threshold | integer | 成功阈值 |

**健康检查配置方式:**

可以分别为 livenessProbe 和 readinessProbe 配置健康检查：

1. **分别配置**: 设置 `liveness_probe` 和 `readiness_probe`
   ```json
   {
     "liveness_probe": {"type": "http", "path": "/live", "port": 8080},
     "readiness_probe": {"type": "http", "path": "/ready", "port": 8080}
   }
   ```

> 说明:
> - **应用模板 (Deployment)**: 每个容器都可以配置健康检查
> - **任务模板 (Job)**: 健康检查可选 (Job通常不需要健康检查)

**Response:** `201 Created` - Returns AppTemplateResponse

### List App Template

**GET** `/api/workflow/app-templates`

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| scope | string | 按范围过滤: `global`/`project` |
| project_id | string | 按项目ID过滤 |

**Response:** Returns AppTemplateListResponse with total count and items.

### Get App Template

**GET** `/api/workflow/app-templates/{template_id}`

**Response:** Returns AppTemplateResponse

### Update App Template

**PUT** `/api/workflow/app-templates/{template_id}`

**Request Body:** Same as create, all fields optional.

**Response:** Returns updated AppTemplateResponse

### Delete App Template

**DELETE** `/api/workflow/app-templates/{tem

**Response:** `200 OK` - Returns SuccessResponse

---

## Job Template API

管理一次性Job模板。

### Create Job Template

**POST** `/api/workflow/job-templates`

创建Job模板 (支持多容器)。

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | 模板名称 |
| description | string | No | 描述 |
| scope | string | No | `global` 或 `project`，默认: `project` |
| project_id | string | Required if scope=project | 项目ID |
| containers | array | Yes | 容器配置列表 (至少一个) |
| ttl_seconds_after_finished | integer | No | 完成后TTL，默认: 3600 |
| backoff_limit | integer | No | 重试次数，默认: 3 |

**Response:** `201 Created` - Returns JobTemplateResponse

### List Job Template

**GET** `/api/workflow/job-templates`

**Query Parameters:** Same as App Template

**Response:** Returns JobTemplateListResponse

### Get Job Template

**GET** `/api/workflow/job-templates/{template_id}`

**Response:** Returns JobTemplateResponse

### Update Job Template

**PUT** `/api/workflow/job-templates/{template_id}`

**Response:** Returns updated JobTemplateResponse

### Delete Job Template

**DELETE** `/api/workflow/job-templates/{template_id}`

**Response:** Returns SuccessResponse

---

## Workflow Template API

管理工作流编排模板，支持拖拽节点定义。

### Create Workflow Template

**POST** `/api/workflow/workflow-templates`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | 模板名称 |
| description | string | No | 描述 |
| scope | string | No | `global` 或 `project` |
| project_id | string | Required if scope=project | 项目ID |
| nodes | array | Yes | 工作流节点 |
| edges | array | Yes | 工作流边/连接 |

**Node Object:**

| Field | Type | Description |
|-------|------|-------------|
| node_id | string | 唯一节点ID |
| node_type | string | `app` 或 `job` |
| template_id | string | 引用的模板ID |
| name | string | 显示名称 |
| position | object | 画布位置 `{x, y}` |
| env_vars | array | 覆盖/添加固定环境变量 |
| volume_mounts | array | 覆盖/添加固定PVC挂载 |
| input_env_vars | array | 输入环境变量 (使用DependencyEnvVar，指定source_node_id) |
| input_volume_mounts | array | 输入挂载 (使用DependencyVolumeMount，指定source_node_id) |
| resources | object | 覆盖资源要求 |
| depends_on | array | 上游节点依赖 |

**DependencyEnvVar Object (工作流节点级 - 指定具体来源):**

| Field | Type | Description |
|-------|------|-------------|
| name | string | 环境变量名 (在当前容器设置) |
| source_node_id | string | 上游节点ID |
| default_value | string | 默认值 |

**DependencyVolumeMount Object (工作流节点级 - 指定具体来源):**

| Field | Type | Description |
|-------|------|-------------|
| mount_path | string | 当前容器的挂载路径 |
| sub_path | string | PVC子目录挂载 (可选) |
| source_node_id | string | 上游节点ID |
| source_pvc_name | string | 指定PVC名 (可选) |
| read_only | boolean | 只读挂载 |

**Edge Object:**

| Field | Type | Description |
|-------|------|-------------|
| edge_id | string | 唯一边ID |
| source | string | 源节点ID |
| target | string | 目标节点ID |
| shared_pvc | string | 共享的PVC名称 |

**Response:** `201 Created` - Returns WorkflowTemplateResponse

### List Workflow Template

**GET** `/api/workflow/workflow-templates`

**Query Parameters:** Same as App Template

**Response:** Returns WorkflowTemplateListResponse

### Get Workflow Template

**GET** `/api/workflow/workflow-templates/{template_id}`

**Response:** Returns WorkflowTemplateResponse

### Update Workflow Template

**PUT** `/api/workflow/workflow-templates/{template_id}`

**Response:** Returns updated WorkflowTemplateResponse

### Delete Workflow Template

**DELETE** `/api/workflow/workflow-templates/{template_id}`

**Response:** Returns SuccessResponse

---

## Workflow Instance API

管理工作流实例生命周期 (创建、运行、删除、日志)。

### Create Workflow Instance

**POST** `/api/workflow/workflow-instances`

创建工作流实例，支持两种运行模式：
- **once**: 一次性运行，工作流执行一次后结束
- **persistent**: 持久化运行，工作流持续有效，可通过触发器多次触发

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | 实例名称 |
| description | string | No | 描述 |
| template_id | string | Yes | 工作流模板ID |
| project_id | string | Yes | 项目ID |
| run_mode | string | No | 运行模式: `once`(默认) 或 `persistent` |
| trigger_type | string | No | 触发器类型: `manual`(默认) 或 `http` |
| trigger_enabled | boolean | No | 是否启用触发器 (默认: false，persistent模式可用) |
| node_configs | object | No | 节点级覆盖配置 |

**Response:** `201 Created` - Returns WorkflowInstanceResponse

### Update Workflow Instance

**PUT** `/api/workflow/workflow-instances/{instance_id}`

更新工作流实例配置。

**Request Body:**

| Field | Type | Description |
|-------|------|-------------|
| name | string | 实例名称 |
| description | string | 描述 |
| trigger_enabled | boolean | 启用/禁用触发器 (persistent模式) |
| is_active | boolean | 设置工作流激活状态 (persistent模式) |

**Response:** Returns updated WorkflowInstanceResponse

### Activate Workflow Instance

**POST** `/api/workflow/workflow-instances/{instance_id}/activate`

激活持久化工作流实例，使其可以接受触发器触发。

**Response:** Returns WorkflowInstanceResponse

### Deactivate Workflow Instance

**POST** `/api/workflow/workflow-instances/{instance_id}/deactivate`

停用持久化工作流实例，拒绝触发器触发。

**Response:** Returns WorkflowInstanceResponse

### Trigger Workflow via HTTP

**POST** `/api/workflow/workflow-instances/triggers/{instance_id}`

通过HTTP请求触发持久化工作流实例执行。

> 注意：此端点需要认证。如需无认证触发，需额外配置。

**Response:** Returns SuccessResponse

**触发器工作流程：**

1. 创建persistent模式的工作流实例，设置 `trigger_type: "http"`, `trigger_enabled: true`
2. 调用激活端点 `POST /activate` 使工作流处于激活状态
3. 外部系统通过HTTP POST请求触发工作流执行
4. 工作流执行完成后保持节点状态，等待下一次触发

### List Workflow Instance

**GET** `/api/workflow/workflow-instances`

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| project_id | string | 按项目ID过滤 |
| status | string | 按状态过滤: `pending`, `running`, `succeeded`, `failed`, `stopped` |
| template_id | string | 按模板ID过滤 |

**Response:** Returns WorkflowInstanceListResponse

### Get Workflow Instance

**GET** `/api/workflow/workflow-instances/{instance_id}`

**Response:** Returns WorkflowInstanceResponse

### Start Workflow Instance

**POST** `/api/workflow/workflow-instances/{instance_id}/start`

启动工作流并为每个节点创建K8S资源 (Deployment/Job 和 Service)。

**Response:** Returns WorkflowInstanceResponse with updated status

### Stop Workflow Instance

**POST** `/api/workflow/workflow-instances/{instance_id}/stop`

停止所有运行中的节点并删除关联的K8S资源。

**Response:** Returns WorkflowInstanceResponse

### Delete Workflow Instance

**DELETE** `/api/workflow/workflow-instances/{instance_id}`

删除工作流实例及所有关联的K8S资源。

**Response:** Returns SuccessResponse

### Get Instance Status

**GET** `/api/workflow/workflow-instances/{instance_id}/status`

从K8S获取实时状态同步。

**Response:**

```json
{
  "instance_id": "string",
  "status": "pending|running|succeeded|failed|stopped",
  "nodes": [...],
  "started_at": "datetime",
  "finished_at": "datetime"
}
```

### Get Node Logs

**GET** `/api/workflow/workflow-instances/{instance_id}/nodes/{node_id}/logs`

获取指定节点的Pod日志。

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| tail_lines | integer | 行数，默认: 100，最大: 10000 |
| previous | boolean | 获取上一个容器的日志 |
| container | string | 多容器Pod的容器名称 |

**Response:** Returns PodLogResponse

---

## Health Check API

### Health Check

**GET** `/api/workflow/health`

健康检查端点。

**Response:**

```json
{
  "status": "ok",
  "service": "secflow-workflow-service"
}
```

### Ready Check

**GET** `/api/workflow/ready`

就绪检查端点。

**Response:**

```json
{
  "status": "ready"
}
```

---

## Data Model

### Template Scope

- `global`: 全局模板，所有项目可见
- `project`: 项目级模板，仅在项目内可见

### Image Pull Policy

- `Always`: 总是拉取镜像
- `IfNotPresent`: 仅当不存在时拉取
- `Never`: 从不拉取

### Workflow Status

- `pending`: 未启动
- `running`: 正在执行
- `succeeded`: 成功完成
- `failed`: 执行失败
- `stopped`: 用户停止

### Node Type

- `app`: Deployment应用
- `job`: 一次性Job

### Run Mode

- `once`: 一次性运行，工作流执行一次后结束
- `persistent`: 持久化运行，工作流持续有效，可通过触发器多次触发

### Trigger Type

- `manual`: 手动触发，仅可通过API手动启动
- `http`: HTTP触发，可通过HTTP请求触发工作流执行

### Service Type

- `ClusterIP`: 集群内部服务 (默认)
- `LoadBalancer`: 负载均衡器类型
- `NodePort`: 节点端口类型

---

## Error Response

所有错误遵循以下格式:

```json
{
  "code": "ERROR_CODE",
  "message": "Error message",
  "details": {}
}
```

**Common Error Codes:**

| Code | HTTP Status | Description |
|------|-------------|-------------|
| NOT_FOUND | 404 | 资源不存在 |
| FORBIDDEN | 403 | 权限不足 |
| UNAUTHORIZED | 401 | 需要认证 |
| VALIDATION_ERROR | 400 | 请求参数无效 |
| CONFLICT | 409 | 资源冲突 |
| INTERNAL_ERROR | 500 | 内部服务器错误 |

---

## K8S Resource Management

### Supported Operations

- **Deployment**: 创建、删除、获取状态
- **Service**: 创建、删除 (支持ClusterIP、LoadBalancer、NodePort)
- **Job**: 创建、删除、获取状态
- **Pod**: 获取日志

### Namespace Convention

资源创建在命名空间: `secflow-{project_id}`

### Resource Naming

- Deployment: `wf-{instance_id[:8]}-{node_id[:8]}`
- Service: `svc-wf-{instance_id[:8]}-{node_id[:8]}`
- Job: `wf-{instance_id[:8]}-{node_id[:8]}`

---

## Configuration

### config.yaml

```yaml
# Database Configuration
database:
  host: "192.168.12.90"
  port: 3306
  username: "secflow"
  password: "Huawei12#$"
  name: "secflow"
  table_prefix: "secflow_platform_workflow_"

# Auth Service
auth_service:
  host: "192.168.12.44"
  port: 10000
  validate_token_path: "/api/auth/validate-human-token"

# Menu Registration
registry:
  menu_service_url: "http://secflow-platform-menu:80"
  service_id: "secflow-workflow"

# Kubernetes
kubernetes:
  connection_mode: "kubeconfig"  # "incluster" or "kubeconfig"
  kubeconfig_path: "/home/runshine/.kube/config"

# App
app:
  host: "0.0.0.0"
  port: 10005
```

---

## Database Tables

| Table Name | Description |
|-----------|-------------|
| secflow_platform_workflow_app_template | 应用模板 |
| secflow_platform_workflow_job_template | 任务模板 |
| secflow_platform_workflow_workflow_template | 工作流模板 |
| secflow_platform_workflow_workflow_instance | 工作流实例 |

---

## Changelog

### v2.3.0 (2026-02-24)

- **健康检查配置增强**: 应用模板和任务模板的容器现在支持分别配置 livenessProbe 和 readinessProbe
  - 新增 `liveness_probe` 字段: 单独配置存活探针
  - 新增 `readiness_probe` 字段: 单独配置就绪探针
- **健康检查作用范围调整**:
  - 应用模板 (Deployment): 每个容器都可以配置健康检查
  - 任务模板 (Job): 健康检查可选
- **依赖对象定义修正**:
  - 应用模板/任务模板的容器配置中使用 `EnvVarInput` 和 `VolumeMountInput` (仅声明需求，不含source_node_id)
  - 工作流节点配置中使用 `DependencyEnvVar` 和 `DependencyVolumeMount` (包含source_node_id)
  - 从应用模板 Container Object 说明中移除了错误的 DependencyEnvVar/DependencyVolumeMount

### v2.2.0 (2026-02-14)

- **运行模式**: 工作流实例支持两种运行模式
  - `once`: 一次性运行，工作流执行一次后结束
  - `persistent`: 持久化运行，工作流持续有效，节点可以是app(Deployment)或job(Job)
- **触发器机制**:
  - 支持手动触发 (`manual`) 和 HTTP触发 (`http`)
  - 持久化工作流可启用触发器，通过HTTP请求自动触发执行
  - 提供激活/停用端点控制工作流是否接受触发
- **依赖定义重构**:
  - 模板级: `input_env_vars`, `input_volume_mounts` (只声明需求)
  - 工作流节点级: `input_env_vars`, `input_volume_mounts` (指定source_node_id)

### v2.1.0 (2026-02-14)

- **PVC子目录挂载**: VolumeMount 和 DependencyVolumeMount 新增 `sub_path` 字段，支持挂载PVC的子目录
  - 例如: `sub_path: "subdir/data"` 可挂载PVC中的 `subdir/data` 目录
- **资源要求定义**: 新增 ResourceRequirements schema，明确定义:
  - `requests`: 最小资源请求 (CPU、内存)
  - `limits`: 资源限制 (CPU、内存)
- **工作流节点资源继承**: 工作流模板节点支持继承任务模板的资源配置，并可在节点级别覆盖
  - 节点级 `resources` 字段可覆盖模板中定义的资源
  - 支持只覆盖 requests 或 limits，或同时覆盖

### v2.0.0 (2024-02-13)

- **多容器支持**: 应用模板和任务模板现在支持多个容器
  - 每个容器可独立定义镜像、命令、环境变量、挂载
  - 每个容器可定义依赖环境变量和依赖挂载 (从上游节点获取值)
  - 健康检查仅对第一个容器生效
- **模板结构变更**: 移除了单容器字段 (image, command, args等)，改为 `containers` 数组
- **依赖解析增强**: 支持容器级依赖和节点级依赖的混合使用

### v1.0.0 (2024-02-12)

- 初始版本发布
- 应用模板管理 (Deployment健康检查、PVC挂载、Service)
- 任务模板管理
- 工作流模板编排 (拖拽、PVC共享、服务依赖)
- 工作流实例生命周期 (创建、启动、停止、删除)
- 节点级日志
- K8S集成 (kubeconfig和serviceaccount)
- 菜单注册和Token认证