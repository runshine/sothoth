# 单应用工作流 API

管理单应用工作流的简化API，适用于只需部署单个应用的场景。

单应用工作流特点：
- 只有一个节点且为应用模板（APP类型）
- 创建工作流和创建节点合并为一个接口
- 简化的生命周期管理
- 其他逻辑与标准工作流一致

## 工作流状态

| 状态 | 说明 |
|------|------|
| pending | 刚创建，未初始化 |
| initializing | 正在初始化中（中间状态） |
| initialized | 已初始化，Deployment/Service已创建 |
| running | 运行中 |
| succeeded | 执行成功 |
| failed | 执行失败 |
| stopped | 已停止 |

## 节点状态

| 状态 | 说明 |
|------|------|
| pending | Pod未运行 |
| not_ready | Pod已运行但未就绪 |
| ready | Pod全部就绪 |
| stopped | 已停止 |
| failed | 执行失败 |

**状态流转:**
```
工作流:
pending -> initializing -> initialized (initialize)
initialized -> running (start)
running -> succeeded/failed/stopped
stopped -> running (start again)
stopped/initialized -> initializing -> initialized (force initialize)

节点:
pending -> not_ready -> ready (Pod启动并就绪)
ready/any -> stopped (stop)
any -> failed (失败)
```

## API 列表

| 方法 | 端点 | 描述 |
|------|------|------|
| POST | `/api/workflow/app-workflows` | 创建单应用工作流 |
| GET | `/api/workflow/app-workflows` | 列表单应用工作流 |
| GET | `/api/workflow/app-workflows/{instance_id}` | 获取单应用工作流详情 |
| PUT | `/api/workflow/app-workflows/{instance_id}` | 更新单应用工作流 |
| DELETE | `/api/workflow/app-workflows/{instance_id}` | 删除单应用工作流 |
| POST | `/api/workflow/app-workflows/{instance_id}/initialize` | 初始化工作流 |
| POST | `/api/workflow/app-workflows/{instance_id}/start` | 启动工作流 |
| POST | `/api/workflow/app-workflows/{instance_id}/stop` | 停止工作流 |
| POST | `/api/workflow/app-workflows/{instance_id}/sync-status` | 同步工作流状态 |
| GET | `/api/workflow/app-workflows/{instance_id}/logs` | 获取工作流日志 |

---

## Create App Workflow

**POST** `/api/workflow/app-workflows`

创建单应用工作流（合并创建工作流和节点）。

**Authentication:** Required

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | 工作流名称 (1-128字符) |
| description | string | No | 描述 |
| project_id | string | Yes | 项目ID |
| template_id | string | Yes | 应用模板ID（必须引用已存在的应用模板） |
| service_name | string | Yes | K8s Service名称 |
| service_ports | array[ServicePort] | Yes | Service端口配置（至少一个端口） |
| service_type | string | No | Service类型: `ClusterIP`(默认), `LoadBalancer`, `NodePort` |
| env_vars | array[EnvVar] | No | 覆盖/添加环境变量 |
| volume_mounts | array[VolumeMount] | No | 覆盖/添加卷挂载 |
| resources | object | No | 覆盖资源需求 |
| replicas | integer | No | 覆盖副本数 (最小值: 1) |
| timeout_seconds | integer | No | 超时时间（秒） |

**ServicePort:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | 端口名称 |
| port | integer | Yes | Service端口 (1-65535) |
| target_port | integer | Yes | 容器端口 (1-65535) |
| protocol | string | No | 协议: `TCP`(默认) 或 `UDP` |

**Request Example:**

```json
{
  "name": "my-nginx-app",
  "description": "Nginx应用服务",
  "project_id": "proj-001",
  "template_id": "wf-tmpl-nginx-abc123",
  "service_name": "nginx-svc",
  "service_ports": [
    {"name": "http", "port": 80, "target_port": 80, "protocol": "TCP"}
  ],
  "service_type": "ClusterIP",
  "replicas": 2
}
```

**Response:** `201 Created`

```json
{
  "id": "wf-inst-my-nginx-xyz789",
  "name": "my-nginx-app",
  "description": "Nginx应用服务",
  "project_id": "proj-001",
  "status": "pending",
  "workflow_type": "simple_app",
  "node": {
    "id": "wf-node-abc456",
    "name": "my-nginx-app-node",
    "node_type": "app",
    "template_id": "wf-tmpl-nginx-abc123",
    "status": "pending",
    "k8s_resource_name": null,
    "service_name": "nginx-svc",
    "message": null,
    "started_at": null,
    "finished_at": null,
    "created_at": "2026-03-12T10:00:00",
    "env_vars": [],
    "volume_mounts": [],
    "resources": null
  },
  "service_name": "nginx-svc",
  "service_ports": [
    {"name": "http", "port": 80, "target_port": 80, "protocol": "TCP"}
  ],
  "template_id": "wf-tmpl-nginx-abc123",
  "template_name": "nginx-template",
  "created_by": "user-001",
  "created_at": "2026-03-12T10:00:00",
  "updated_at": "2026-03-12T10:00:00",
  "started_at": null,
  "finished_at": null,
  "message": null
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 201 | 创建成功 |
| 400 | 请求参数无效 |
| 401 | 未认证 |
| 403 | 无权限使用模板 |
| 404 | 应用模板不存在 |

---

## List App Workflows

**GET** `/api/workflow/app-workflows`

列表单应用工作流。

**Authentication:** Required

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| project_id | string | 按项目ID过滤 |
| status | string | 按状态过滤: `pending`, `initialized`, `running`, `stopped`, `failed` |

**Response:** `200 OK`

```json
{
  "total": 2,
  "items": [
    {
      "id": "wf-inst-my-nginx-xyz789",
      "name": "my-nginx-app",
      "status": "running",
      "workflow_type": "simple_app",
      "node": {...},
      "template_id": "wf-tmpl-nginx-abc123",
      "template_name": "nginx-template",
      "created_by": "user-001",
      "created_at": "2026-03-12T10:00:00"
    },
    {
      "id": "wf-inst-my-redis-xyz123",
      "name": "my-redis-app",
      "status": "initialized",
      "workflow_type": "simple_app",
      "node": {...},
      "template_id": "wf-tmpl-redis-def456",
      "template_name": "redis-template",
      "created_by": "user-001",
      "created_at": "2026-03-11T10:00:00"
    }
  ]
}
```

---

## Get App Workflow

**GET** `/api/workflow/app-workflows/{instance_id}`

获取单应用工作流详情。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 工作流实例ID |

**Response:** `200 OK`

返回与创建响应相同的数据结构。

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | 成功 |
| 401 | 未认证 |
| 403 | 无权限访问 |
| 404 | 工作流不存在 |

---

## Update App Workflow

**PUT** `/api/workflow/app-workflows/{instance_id}`

更新单应用工作流配置。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 工作流实例ID |

**Request Body:**

| Field | Type | Description |
|-------|------|-------------|
| name | string | 工作流名称 |
| description | string | 描述 |
| service_name | string | Service名称 |
| service_ports | array[ServicePort] | Service端口配置 |
| service_type | string | Service类型 |
| env_vars | array[EnvVar] | 环境变量 |
| volume_mounts | array[VolumeMount] | 卷挂载 |
| resources | object | 资源需求 |
| replicas | integer | 副本数 |

**注意:** 只能在 `pending`、`initialized`、`stopped` 状态下修改配置。

**Response:** `200 OK`

---

## Delete App Workflow

**DELETE** `/api/workflow/app-workflows/{instance_id}`

删除单应用工作流。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 工作流实例ID |

**Description:**

- 如果运行中则先停止
- 删除所有关联的K8S资源（Deployment、Service）
- 从数据库删除实例和节点

**Response:** `200 OK`

```json
{
  "message": "App workflow wf-inst-my-nginx-xyz789 deleted successfully"
}
```

---

## Initialize App Workflow

**POST** `/api/workflow/app-workflows/{instance_id}/initialize`

初始化单应用工作流（创建Deployment和Service）。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 工作流实例ID |

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| force | boolean | 强制重新初始化（删除已存在的资源后重新创建），默认: false |

**Description:**

初始化流程：
1. 验证应用模板存在
2. 检查Service配置（service_name、service_ports）
3. 创建Deployment
4. 创建Service
5. 根据Pod状态设置节点状态

**前置条件:**
- 状态为 `pending`: 正常初始化
- 状态为 `initialized` 或 `stopped` 且 `force=true`: 强制重新初始化

**Response:** `200 OK`

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | 初始化成功 |
| 400 | 状态不正确或参数无效 |
| 401 | 未认证 |
| 403 | 无权限 |
| 404 | 工作流或模板不存在 |
| 500 | K8S资源创建失败 |

---

## Start App Workflow

**POST** `/api/workflow/app-workflows/{instance_id}/start`

启动单应用工作流。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 工作流实例ID |

**Description:**

- 检查Deployment状态
- 更新工作流状态为 `running`
- 更新节点状态

**前置条件:** 工作流状态为 `initialized` 或 `stopped`

**Response:** `200 OK`

---

## Stop App Workflow

**POST** `/api/workflow/app-workflows/{instance_id}/stop`

停止单应用工作流。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 工作流实例ID |

**Description:**

- 删除Deployment
- 删除Service
- 更新状态为 `stopped`

**前置条件:** 工作流状态为 `initialized` 或 `running`

**Response:** `200 OK`

---

## Sync App Workflow Status

**POST** `/api/workflow/app-workflows/{instance_id}/sync-status`

同步单应用工作流状态。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 工作流实例ID |

**Description:**

- 从K8S获取实时状态并同步
- 更新节点状态
- 更新工作流整体状态
- 可手动或定期调用

**Response:** `200 OK`

---

## Get App Workflow Logs

**GET** `/api/workflow/app-workflows/{instance_id}/logs`

获取单应用工作流日志。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 工作流实例ID |

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| tail_lines | integer | 返回日志行数，默认: 100，范围: 1-10000 |
| container | string | 容器名称（多容器Pod时使用） |
| previous | boolean | 获取上一个容器的日志，默认: false |
| timestamps | boolean | 包含时间戳，默认: true |

**Response:** `200 OK`

```json
{
  "workflow_id": "wf-inst-my-nginx-xyz789",
  "node_id": "wf-node-abc456",
  "resource_name": "wf-xyz789-abc456",
  "pod_name": "wf-xyz789-abc456-xxx",
  "namespace": "secflow-proj-001",
  "logs": "2026-03-12T10:00:00.000Z Starting nginx...\n...",
  "container": null,
  "previous": false
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | 成功 |
| 400 | 工作流未初始化 |
| 401 | 未认证 |
| 403 | 无权限访问 |
| 404 | 工作流或Pod不存在 |

---

## 与标准工作流的区别

| 特性 | 标准工作流 | 单应用工作流 |
|------|-----------|-------------|
| 节点数量 | 支持多节点 | 仅支持单节点 |
| 节点类型 | app、job | 仅app |
| 创建方式 | 分步创建或一次性创建 | 合并创建 |
| 依赖关系 | 支持节点依赖 | 无依赖 |
| 模板引用 | 应用模板、任务模板 | 仅应用模板 |
| Service配置 | 节点级别配置 | 创建时必须指定 |

## 数据存储

单应用工作流复用标准工作流的数据表：

- `WorkflowInstance` - 工作流实例（通过 `run_mode = "simple_app"` 标识）
- `WorkflowNodeInstance` - 节点实例
