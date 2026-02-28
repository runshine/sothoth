# 工作流实例 API

管理工作流实例生命周期 (创建、运行、删除、日志)。
工作流实例中的每个节点直接引用应用模板(AppTemplate)或任务模板(JobTemplate)。
支持两种创建方式：
1. **直接创建**: 创建实例时直接指定所有节点和边
2. **先创建空白实例**: 先创建无节点的空白实例，然后通过节点API逐个添加节点

## API 列表

| 方法 | 端点 | 描述 |
|------|------|------|
| POST | `/api/workflow/workflow-instances` | 创建工作流实例 |
| GET | `/api/workflow/workflow-instances` | 列表工作流实例 |
| GET | `/api/workflow/workflow-instances/{instance_id}` | 获取工作流实例详情 |
| PUT | `/api/workflow/workflow-instances/{instance_id}` | 更新工作流实例 |
| POST | `/api/workflow/workflow-instances/{instance_id}/initialize` | 初始化工作流(创建Deployment) |
| POST | `/api/workflow/workflow-instances/{instance_id}/start` | 启动工作流 |
| POST | `/api/workflow/workflow-instances/{instance_id}/sync-status` | 同步工作流状态 |
| POST | `/api/workflow/workflow-instances/{instance_id}/stop` | 停止工作流 |
| POST | `/api/workflow/workflow-instances/{instance_id}/activate` | 激活持久化工作流 |
| POST | `/api/workflow/workflow-instances/{instance_id}/deactivate` | 停用持久化工作流 |
| DELETE | `/api/workflow/workflow-instances/{instance_id}` | 删除工作流实例 |

---

## Create Workflow Instance

**POST** `/api/workflow/workflow-instances`

创建工作流实例。

**Authentication:** Required

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | 实例名称 (1-128字符) |
| description | string | No | 描述 |
| project_id | string | Yes | 项目ID |
| nodes | array[WorkflowNodeConfig] | No | 工作流节点列表 (可为空后续通过节点API添加) |
| edges | array[WorkflowEdgeConfig] | No | 工作流边/连接列表 |
| run_mode | string | No | 运行模式: `once`(默认) 或 `persistent` |
| trigger_type | string | No | 触发器类型: `manual`(默认) 或 `http` |
| trigger_enabled | boolean | No | 是否启用触发器默认: false |

**WorkflowNodeConfig:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| node_type | string | Yes | 节点类型: `app` 或 `job` |
| template_id | string | Yes | 应用模板ID或任务模板ID |
| name | string | Yes | 显示名称 |
| position | object | No | 画布位置 `{x: 0.0, y: 0.0}` (浮点数) |
| env_vars | array[EnvVar] | No | 覆盖/添加固定环境变量 (用于满足模板依赖) |
| volume_mounts | array[VolumeMount] | No | 覆盖/添加固定PVC挂载 (用于满足模板依赖) |
| resources | object | No | 覆盖资源要求 |
| timeout_seconds | integer | No | 节点超时时间(秒): 应用模板默认300(5分钟), 任务模板默认3600(1小时), 不含镜像拉取时间 |

**注意：**
- 节点ID由系统自动生成，用户不需要指定
- 不同节点之间没有依赖关系，创建节点时不需要指定 `input_env_vars`、`input_volume_mounts` 和 `depends_on`

**WorkflowEdgeConfig:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| edge_id | string | Yes | 唯一边ID |
| source | string | Yes | 源节点ID |
| target | string | Yes | 目标节点ID |
| shared_pvc | string | No | 共享的PVC名称 |

**Request Example:**

```json
{
  "name": "my-workflow-instance",
  "description": "Production workflow run",
  "project_id": "proj-001",
  "nodes": [
    {
      "node_type": "app",
      "template_id": "wf-tmpl-app-001",
      "name": "Frontend Service",
      "position": {"x": 100, "y": 100},
      "env_vars": [{"name": "API_URL", "value": "http://backend:8080"}]
    },
    {
      "node_type": "job",
      "template_id": "wf-tmpl-job-001",
      "name": "Data Processor",
      "position": {"x": 100, "y": 300}
    }
  ],
  "edges": [
    {
      "edge_id": "edge-001",
      "source": "node-id-001",
      "target": "node-id-002"
    }
  ],
  "run_mode": "once",
  "trigger_type": "manual"
}
```

**Response:** `201 Created`

**WorkflowInstanceResponse:**

```json
{
  "id": "wf-inst-my-workflow-jkl012",
  "name": "my-workflow-instance",
  "description": "Production workflow run",
  "project_id": "proj-001",
  "status": "pending",
  "run_mode": "once",
  "trigger_type": "manual",
  "trigger_enabled": false,
  "trigger_url": null,
  "is_active": true,
  "run_count": 0,
  "last_run_at": null,
  "nodes": [...],
  "created_by": "user-001",
  "started_at": null,
  "finished_at": null,
  "created_at": "2026-02-25T10:00:00",
  "updated_at": "2026-02-25T10:00:00"
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 201 | 创建成功 |
| 400 | 请求参数无效 |
| 401 | 未认证 |
| 403 | 无权限使用模板 |
| 404 | 模板不存在 |
| 409 | 资源冲突 |

---

## List Workflow Instance

**GET** `/api/workflow/workflow-instances`

列表工作流实例。

**Authentication:** Required

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| project_id | string | 按项目ID过滤 |
| status | string | 按状态过滤: `pending`, `running`, `succeeded`, `failed`, `stopped` |

**Response:** `200 OK`

---

## Get Workflow Instance

**GET** `/api/workflow/workflow-instances/{instance_id}`

获取工作流实例详情。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 实例ID |

**Response:** `200 OK`

---

## Update Workflow Instance

**PUT** `/api/workflow/workflow-instances/{instance_id}`

更新工作流实例配置。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 实例ID |

**Request Body:**

| Field | Type | Description |
|-------|------|-------------|
| name | string | 实例名称 |
| description | string | 描述 |
| trigger_enabled | boolean | 启用/禁用触发器 (仅persistent模式可用) |
| is_active | boolean | 设置工作流激活状态 (仅persistent模式可用) |

**Response:** `200 OK`

---

## Initialize Workflow Instance

**POST** `/api/workflow/workflow-instances/{instance_id}/initialize`

初始化工作流实例（仅创建Deployment和Service，不启动工作流）。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 实例ID |

**Description:**

对于应用模板(AppTemplate)形成的节点:
- 创建节点的配置
- 创建对应的K8S Deployment
- 如果配置了创建Service，则创建对应的K8S Service
- 不创建JOB（JOB在start时创建并执行）

**注意:**
- 只初始化应用模板节点，不启动工作流执行
- 工作流状态保持为PENDING
- 创建完成后可通过start API启动工作流

**Response:** `200 OK`

---

## Start Workflow Instance

**POST** `/api/workflow/workflow-instances/{instance_id}/start`

启动工作流实例。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 实例ID |

**Description:**

- 使用WorkflowEngine进行拓扑执行和依赖检查
- 检测并防止循环依赖
- 并发执行就绪节点
- 处理环境变量和挂载依赖

**Response:** `200 OK`

---

## Sync Workflow Status

**POST** `/api/workflow/workflow-instances/{instance_id}/sync-status`

同步工作流实例状态。

**Authentication:** Required

**Description:**

- 从K8S获取实时状态并同步
- 更新所有节点状态
- 触发执行就绪节点
- 可手动或定期调用

**Response:** `200 OK`

---

## Stop Workflow Instance

**POST** `/api/workflow/workflow-instances/{instance_id}/stop`

停止工作流实例。

**Authentication:** Required

**Description:**

- 停止所有运行中的节点
- 删除关联的K8S资源 (Deployment/Job/Service)

**Response:** `200 OK`

---

## Activate Workflow Instance

**POST** `/api/workflow/workflow-instances/{instance_id}/activate`

激活持久化工作流实例。

**Authentication:** Required

**Description:**

- 激活持久化工作流实例使其可以接受触发器触发
- 仅对persistent模式有效

**Response:** `200 OK`

---

## Deactivate Workflow Instance

**POST** `/api/workflow/workflow-instances/{instance_id}/deactivate`

停用持久化工作流实例。

**Authentication:** Required

**Description:**

- 停用持久化工作流实例拒绝触发器触发
- 不停止运行中的工作流
- 仅对persistent模式有效

**Response:** `200 OK`

---

## Delete Workflow Instance

**DELETE** `/api/workflow/workflow-instances/{instance_id}`

删除工作流实例。

**Authentication:** Required

**Description:**

- 如果运行中则先停止
- 删除所有关联的K8S资源
- 从数据库删除实例和节点

**Response:** `200 OK`

**SuccessResponse:**

```json
{
  "message": "Workflow instance wf-inst-my-workflow-jkl012 deleted successfully"
}
```