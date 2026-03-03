# 工作流实例 API

管理工作流实例生命周期 (创建、运行、删除、日志)。
工作流实例中的每个节点直接引用应用模板(AppTemplate)或任务模板(JobTemplate)。
支持两种创建方式：
1. **直接创建**: 创建实例时直接指定所有节点和边
2. **先创建空白实例**: 先创建无节点的空白实例，然后通过节点API逐个添加节点

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

**APP节点状态：**

| 状态 | 说明 |
|------|------|
| pending | Pod未运行 |
| not_ready | Pod已运行但未就绪 |
| ready | Pod全部就绪 |
| stopped | 已停止 |
| failed | 执行失败 |

**JOB节点状态：**

| 状态 | 说明 |
|------|------|
| pending | 等待执行 |
| running | 执行中 |
| succeeded | 执行成功 |
| failed | 执行失败 |

**状态流转:**
```
工作流:
pending -> initializing -> initialized (initialize)
initialized -> running (start)
running -> succeeded (all nodes complete) / failed (any node fails) / stopped (stop)
stopped -> running (start again)
stopped/initialized -> initializing -> initialized (force initialize)
initialized/running/stopped/failed/succeeded -> pending (uninitialize)

APP节点:
pending -> not_ready -> ready (Pod启动并就绪)
ready/any -> stopped (stop)
any -> failed (失败)

JOB节点:
pending -> running -> succeeded/failed (Job执行)
```

**持久化模式触发器:**
- initialized/running 状态可接受触发
- trigger 保持 running 状态直到执行完成

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
| POST | `/api/workflow/workflow-instances/{instance_id}/uninitialize` | 反初始化工作流(删除K8S资源并重置) |
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
| create_service | boolean | No | 是否创建K8s Service (仅app类型节点有效), 默认: true |
| service_name | string | Conditional | K8s Service名称 (当create_service=true时必填) |
| service_ports | array[ServicePort] | Conditional | Service端口配置 (当create_service=true时必填) |
| service_type | string | No | Service类型: `ClusterIP`(默认), `LoadBalancer`, `NodePort` (仅app类型节点有效) |

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
      "env_vars": [{"name": "API_URL", "value": "http://backend:8080"}],
      "create_service": true,
      "service_name": "frontend-svc",
      "service_ports": [{"name": "http", "port": 80, "target_port": 8080}],
      "service_type": "ClusterIP"
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
| status | string | 按状态过滤: `pending`, `initializing`, `initialized`, `running`, `stopped` |

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
| edges | array[WorkflowEdgeConfig] | 更新边/连接 (仅 pending 状态可修改) |
| trigger_enabled | boolean | 启用/禁用触发器 (仅persistent模式可用) |
| is_active | boolean | 设置工作流激活状态 (仅persistent模式可用) |

**注意:**
- `edges` 字段只能在 `pending` 状态下修改
- 其他字段可以在 `pending`、`initialized`、`stopped` 状态下修改

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

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| force | boolean | No | 强制重新初始化（删除已存在的资源后重新创建），默认: false |

**Request Example:**

```json
{
  "force": false
}
```

**Description:**

对于不同类型的节点，初始化逻辑不同：

**JOB类型节点:**
- 不创建任何K8S资源
- 状态保持 `pending`（等待start时创建Job并执行）

**APP类型节点:**
- 服务配置在工作流节点实例化时指定（`create_service=true` 且 `service_ports` 不为空）
- 必须在节点配置中定义 `service_name`（用于创建Service）
- 创建对应的K8S Deployment
- 使用节点配置中定义的 `service_name` 创建K8S Service（不能使用自动生成的名称如 `wf-8817564c-632245d0`）
- 如果节点未定义Service或Service创建失败，则上报初始化失败
- 根据Pod状态设置节点状态：
  - `pending`: Pod未运行
  - `not_ready`: Pod已运行但未就绪
  - `ready`: Pod全部就绪

**初始化流程:**
1. 接收初始化请求，将状态设置为 `initializing`
2. 对于JOB节点：不创建资源，保持 `pending` 状态
3. 对于APP节点：
   - 检查节点配置是否定义了Service（`create_service=true` 且 `service_ports` 不为空）
   - 检查节点配置是否定义了 `service_name`
   - 创建 Deployment
   - 使用节点配置中的 `service_name` 创建 Service
   - 检查 Pod 状态设置节点状态（pending/not_ready/ready）
   - 如果任一步骤失败，则上报初始化失败
4. 初始化完成后，状态变为 `initialized` 或 `failed`

**强制初始化 (force=true):**
- 前置条件: 工作流状态为 `initialized` 或 `stopped`
- 先删除已存在的 K8S 资源 (Deployment/Service)
- 然后重新创建 Deployment 和 Service
- 用于重新初始化场景

**前置条件:**
- 状态为 `pending`: 正常初始化
- 状态为 `initialized` 或 `stopped` 且 `force=true`: 强制重新初始化

**注意:**
- JOB节点初始化时不创建任何K8S资源，状态保持 `pending`
- APP节点必须在节点配置中定义Service配置（`create_service=true`、`service_ports`不为空、`service_name`不为空）
- APP节点创建Service时使用节点配置中定义的`service_name`，不能使用自动生成的名称
- APP节点初始化后根据Pod状态设置节点状态：`pending`（未运行）、`not_ready`（运行中未就绪）、`ready`（就绪）
- 如果APP节点未定义Service配置，初始化会失败
- 初始化成功后工作流状态变为 `initialized`
- 如果状态为 `initializing`，表示正在初始化中，不能重复调用

**Response:** `200 OK`

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | 初始化成功 |
| 400 | 状态不正确或正在初始化中 |
| 401 | 未认证 |
| 403 | 无权限 |
| 404 | 实例不存在 |

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

**前置条件:** 工作流状态为 `pending`、`initialized` 或 `stopped`

**Response:** `200 OK`

---

## Sync Workflow Status

**POST** `/api/workflow/workflow-instances/{instance_id}/sync-status`

同步工作流实例状态。

**Authentication:** Required

**Description:**

- 从K8S获取实时状态并同步
- 更新所有节点状态
- 更新工作流整体状态
- 可手动或定期调用
- 允许在任何状态下调用，用于手动状态同步和异常状态恢复

**注意:**
- 当工作流处于 `pending` 状态时，只同步状态，不会启动就绪节点
- 只有已初始化的工作流（状态不为 `pending`）才会检查并启动就绪节点
- 这确保了未初始化的工作流不会意外创建 K8S 资源

**Response:** `200 OK`

---

## Stop Workflow Instance

**POST** `/api/workflow/workflow-instances/{instance_id}/stop`

停止工作流实例。

**Authentication:** Required

**Description:**

- 停止所有运行中的节点
- 删除关联的K8S资源 (Deployment/Job/Service)

**前置条件:** 工作流状态为 `initialized` 或 `running`

**注意:** 停止后状态变为 `stopped`

**Response:** `200 OK`

---

## Uninitialize Workflow Instance

**POST** `/api/workflow/workflow-instances/{instance_id}/uninitialize`

反初始化工作流实例（删除所有K8S资源并重置状态）。

**Authentication:** Required

**Description:**

删除工作流初始化过程中创建的所有 K8S 资源，包括但不限于：
- **Deployment**: 应用模板节点创建的 Deployment
- **Service**: 应用模板节点创建的 Service
- **Job**: 任务模板节点创建的 Job
- **其他相关资源**: 与工作流相关的所有 K8S 资源

同时重置状态：
- 清空所有节点的 K8S 资源信息（`k8s_resource_name`、`k8s_resource_type`、`service_name`）
- 清空所有节点的时间戳（`started_at`、`finished_at`、`message`）
- 将所有节点状态重置为 `pending`
- 将工作流状态重置为 `pending`

**前置条件:** 工作流状态为 `initialized`、`running`、`stopped`、`failed` 或 `succeeded`

**用途:**

- 完全重置工作流到初始状态
- 清理所有 K8S 资源后重新配置
- 修复初始化问题后重新开始
- 允许重新修改节点和边配置

**与 stop 的区别:**

| 操作 | stop | uninitialize |
|------|------|--------------|
| 删除 K8S 资源 | 是 | 是 |
| 节点最终状态 | stopped | pending |
| 工作流最终状态 | stopped | pending |
| 可重新修改配置 | 否 | 是 |
| 可重新初始化 | 否（需要 force initialize） | 是（直接 initialize） |
| 可重新初始化 | 否（需要 force initialize） | 是（直接 initialize） |

**Response:** `200 OK`

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | 反初始化成功 |
| 400 | 状态不正确 |
| 401 | 未认证 |
| 403 | 无权限 |
| 404 | 实例不存在 |

---

## Activate Workflow Instance

**POST** `/api/workflow/workflow-instances/{instance_id}/activate`

激活持久化工作流实例。

**Authentication:** Required

**Description:**

- 激活持久化工作流实例使其可以接受触发器触发
- 仅对persistent模式有效

**前置条件:** 工作流状态为 `initialized` 或 `stopped`

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
