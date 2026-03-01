# 工作流节点 API

管理工作流实例中的节点。每个节点由应用模板(AppTemplate)或任务模板(JobTemplate)实例化而来。

## API 列表

| 方法 | 端点 | 描述 |
|------|------|------|
| POST | `/api/workflow/workflow-instances/{instance_id}/nodes` | 创建工作流节点 |
| GET | `/api/workflow/workflow-instances/{instance_id}/nodes` | 列表工作流节点 |
| GET | `/api/workflow/workflow-instances/{instance_id}/nodes/{node_id}` | 获取工作流节点详情 |
| PUT | `/api/workflow/workflow-instances/{instance_id}/nodes/{node_id}` | 更新工作流节点 |
| DELETE | `/api/workflow/workflow-instances/{instance_id}/nodes/{node_id}` | 删除工作流节点 |
| GET | `/api/workflow/workflow-instances/{instance_id}/nodes/{node_id}/logs` | 获取节点日志 |

---

## Create Workflow Node

**POST** `/api/workflow/workflow-instances/{instance_id}/nodes`

在工作流实例中添加节点。

**前置条件:** 工作流状态必须为 `pending`

**注意：**
- 节点ID由系统自动生成，用户不需要指定
- 不同节点之间没有依赖关系，无需指定 `depends_on`
- `env_vars` 和 `volume_mounts` 用于实例化模板时传递环境变量和挂载参数以满足模板依赖要求
- 创建时会校验是否满足指定ID模板的依赖条件，如果不满足则返回未满足的依赖详情
- 工作流初始化后（状态不为 pending）不允许添加节点

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 实例ID |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| node_type | string | Yes | 节点类型: `app` 或 `job` |
| template_id | string | Yes | 应用模板ID或任务模板ID |
| name | string | Yes | 显示名称 |
| position | object | No | 画布位置 `{x: 0.0, y: 0.0}` (浮点数) |
| env_vars | array[EnvVar] | No | 覆盖/添加固定环境变量 (用于满足模板依赖) |
| volume_mounts | array[VolumeMount] | No | 覆盖/添加固定PVC挂载 (用于满足模板依赖) |
| resources | object | No | 覆盖资源要求 |
| timeout_seconds | integer | No | 节点超时时间(秒) |

**Response:** `201 Created`

**WorkflowNodeInstanceResponse:**

```json
{
  "id": "wf-node-001-mno345",
  "node_type": "app",
  "template_id": "wf-tmpl-app-001",
  "name": "Frontend Service",
  "status": "pending",
  "k8s_resource_name": null,
  "k8s_resource_type": null,
  "depends_on": [],
  "downstream_node_ids": [],
  "service_name": null,
  "timeout_seconds": null,
  "started_at": null,
  "finished_at": null,
  "message": null,
  "position": {"x": 100.0, "y": 100.0},
  "env_vars": [{"name": "API_URL", "value": "http://backend:8080"}],
  "volume_mounts": [],
  "resources": null,
  "input_env_vars": [],
  "input_volume_mounts": [],
  "created_at": "2026-02-25T10:00:00"
}
```

**错误响应 - 依赖不满足 (400 Bad Request):**

```json
{
  "code": "VALIDATION_ERROR",
  "message": "Template dependency not satisfied for node node1: [...]",
  "details": [
    {
      "type": "env_var",
      "container": "main",
      "name": "DATABASE_URL",
      "message": "Container 'main' requires env_var 'DATABASE_URL' but not provided"
    },
    {
      "type": "volume_mount",
      "container": "main",
      "mount_path": "/data",
      "message": "Container 'main' requires volume_mount at '/data' but not provided"
    }
  ]
}
```

---

## List Workflow Nodes

**GET** `/api/workflow/workflow-instances/{instance_id}/nodes`

列出工作流实例中的所有节点。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 实例ID |

**Response:** `200 OK`

---

## Get Workflow Node

**GET** `/api/workflow/workflow-instances/{instance_id}/nodes/{node_id}`

获取工作流节点详情。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 实例ID |
| node_id | string | 节点ID (数据库主键) |

**Response:** `200 OK`

---

## Update Workflow Node

**PUT** `/api/workflow/workflow-instances/{instance_id}/nodes/{node_id}`

更新工作流节点配置。

**前置条件:** 工作流状态必须为 `pending`

**注意：**
- 不同节点之间没有依赖关系，无需指定 `depends_on`
- 更新时可修改与创建时相同的配置字段
- 工作流初始化后（状态不为 pending）不允许修改节点

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 实例ID |
| node_id | string | 节点ID (数据库主键) |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | No | 显示名称 |
| position | object | No | 画布位置 `{x: 0.0, y: 0.0}` |
| env_vars | array[EnvVar] | No | 覆盖/添加固定环境变量 (用于满足模板依赖) |
| volume_mounts | array[VolumeMount] | No | 覆盖/添加固定PVC挂载 (用于满足模板依赖) |
| resources | object | No | 覆盖资源要求 |
| input_env_vars | array[DependencyEnvVar] | No | 输入环境变量依赖 |
| input_volume_mounts | array[DependencyVolumeMount] | No | 输入挂载依赖 |

**Response:** `200 OK`

---

## Delete Workflow Node

**DELETE** `/api/workflow/workflow-instances/{instance_id}/nodes/{node_id}`

删除工作流节点。

**前置条件:** 工作流状态必须为 `pending`

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 实例ID |
| node_id | string | 节点ID (数据库主键) |

**Description:**

- 工作流初始化后（状态不为 pending）不允许删除节点
- 删除节点后需要手动更新edges移除相关连线

**Response:** `200 OK`

**SuccessResponse:**

```json
{
  "message": "Workflow node wf-node-001-mno345 deleted successfully"
}
```

---

## Get Node Logs

**GET** `/api/workflow/workflow-instances/{instance_id}/nodes/{node_id}/logs`

获取指定节点的Pod日志。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 实例ID |
| node_id | string | 节点ID (数据库主键) |

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| tail_lines | integer | 行数默认: 100最大: 10000 |
| container | string | 多容器Pod的容器名称 |
| previous | boolean | 获取上一个容器的日志默认: false |
| timestamps | boolean | 包含时间戳默认: true |

**Response:** `200 OK`

**PodLogResponse:**

```json
{
  "resource_name": "wf-jkl012-node-001",
  "pod_name": "wf-jkl012-node-001-abc123-def456",
  "namespace": "secflow-proj-001",
  "logs": "2026-02-25T10:05:00 Starting application...\n2026-02-25T10:05:01 Server listening on port 8080",
  "container": "web-container",
  "previous": false
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | 获取成功 |
| 400 | 节点未启动无法获取日志 |
| 401 | 未认证 |
| 403 | 无权限 |
| 404 | 实例或节点不存在 |

---

## Update Workflow Edge

**POST** `/api/workflow/workflow-instances/{instance_id}/edges`

添加、更新或删除工作流边。

**前置条件:** 工作流状态必须为 `pending`

**注意:** 工作流初始化后（状态不为 pending）不允许修改边

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 实例ID |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| edge_id | string | Conditional | 边ID (add/update/delete操作需要) |
| source | string | Conditional | 源节点ID (add操作需要) |
| target | string | Conditional | 目标节点ID (add操作需要) |
| shared_pvc | string | No | 共享PVC名称 |
| action | string | Yes | 操作: `add`, `update`, `delete` |

**Request Example (add):**

```json
{
  "edge_id": "edge-001",
  "source": "node-001",
  "target": "node-002",
  "action": "add"
}
```

**Request Example (delete):**

```json
{
  "edge_id": "edge-001",
  "action": "delete"
}
```

**Response:** `200 OK`