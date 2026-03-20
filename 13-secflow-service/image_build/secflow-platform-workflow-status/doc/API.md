# SecFlow 工作流状态管理服务 API 手册

## API 汇总

| 模块 | 方法 | 端点 | 功能 | 认证 |
|------|------|------|------|------|
| **健康检查** | GET | `/api/workflow-status/health` | 服务健康检查 | 否 |
| **就绪检查** | GET | `/api/workflow-status/ready` | 服务就绪检查 | 否 |
| **节点状态** | POST | `/api/workflow-status/nodes` | 记录节点初始状态 | 是 |
| | POST | `/api/workflow-status/nodes/{node_id}/sync` | 同步单个节点状态 | 是 |
| | GET | `/api/workflow-status/nodes/{node_id}` | 获取节点状态详情 | 是 |
| | PUT | `/api/workflow-status/nodes/{node_id}` | 更新节点状态 | 是 |
| | GET | `/api/workflow-status/nodes/{node_id}/logs` | 获取节点实时日志 | 是 |
| | GET | `/api/workflow-status/nodes/{node_id}/logs/stored` | 获取节点存储日志 | 是 |
| | POST | `/api/workflow-status/nodes/{node_id}/logs/init` | 保存初始化日志 | 是 |
| | POST | `/api/workflow-status/nodes/{node_id}/logs/execution` | 保存执行日志 | 是 |
| | GET | `/api/workflow-status/nodes/{node_id}/history` | 获取节点状态变更历史 | 是 |
| **工作流实例** | POST | `/api/workflow-status/instances/{instance_id}/sync-all` | 批量同步工作流节点状态 | 是 |
| | GET | `/api/workflow-status/instances/{instance_id}` | 获取工作流实例状态 | 是 |
| | GET | `/api/workflow-status/instances/{instance_id}/nodes` | 获取工作流所有节点状态 | 是 |
| | GET | `/api/workflow-status/instances/{instance_id}/history` | 获取工作流状态变更历史 | 是 |
| | GET | `/api/workflow-status/instances` | 获取工作流状态列表 | 是 |
| **统计** | GET | `/api/workflow-status/statistics` | 获取状态统计信息 | 是 |

---

## 通用说明

### 认证方式

所有需要认证的接口都必须在请求头中携带Token:

```
Authorization: Bearer <token>
```

### 项目参数

所有资源操作接口都需要通过 `project_id` 查询参数指定项目:

```
GET /api/workflow-status/instances?project_id=xxx
```

### 响应格式

成功响应:
```json
{
  "message": "操作成功",
  "data": { ... }
}
```

错误响应:
```json
{
  "code": "ERROR_CODE",
  "message": "错误信息",
  "details": { ... }
}
```

---

## 状态常量定义

### APP节点状态 (AppNodeStatus)

APP节点对应Kubernetes的Deployment资源，状态反映Pod的运行情况。

| 状态 | 常量 | 说明 | 状态转换 |
|------|------|------|----------|
| Pending | `AppNodeStatus.PENDING` | Pod未运行，等待启动 | 初始状态 |
| Not_ready | `AppNodeStatus.NOT_READY` | Pod已运行但未就绪 | Pending → Not_ready |
| Ready | `AppNodeStatus.READY` | Pod全部就绪，服务可用 | Not_ready → Ready |

**状态流转图:**
```
Pending → Not_ready → Ready
    ↑           ↓
    └───────────┘ (Pod重启时可能回退)
```

### JOB节点状态 (JobNodeStatus)

JOB节点对应Kubernetes的Job资源，状态反映Job的执行情况。

| 状态 | 常量 | 说明 | 状态转换 |
|------|------|------|----------|
| Pending | `JobNodeStatus.PENDING` | 等待执行 | 初始状态 |
| Running | `JobNodeStatus.RUNNING` | 执行中 | Pending → Running |
| Succeeded | `JobNodeStatus.SUCCEEDED` | 执行成功 | Running → Succeeded (终态) |
| Failed | `JobNodeStatus.FAILED` | 执行失败 | Running → Failed (终态) |

**状态流转图:**
```
Pending → Running → Succeeded (终态)
                ↘ Failed (终态)
```

### 工作流状态 (WorkflowStatus)

工作流状态由所有节点状态聚合得出。

| 状态 | 常量 | 说明 | 判断条件 |
|------|------|------|----------|
| Failed | `WorkflowStatus.FAILED` | 工作流失败 | 有Job节点失败 |
| Running | `WorkflowStatus.RUNNING` | 工作流运行中 | 有Job节点Running或APP节点Not_ready |
| Succeeded | `WorkflowStatus.SUCCEEDED` | 工作流成功 | 全部节点Ready或Succeeded |
| Pending | `WorkflowStatus.PENDING` | 等待中 | 其他情况 |

**状态优先级:** Failed > Running > Succeeded > Pending

---

## 健康检查

### GET /api/workflow-status/health

服务健康检查

**参数**: 无

**响应**:
```json
{
  "status": "healthy"
}
```

---

### GET /api/workflow-status/ready

服务就绪检查

**参数**: 无

**响应**:
```json
{
  "status": "ready"
}
```

---

## 节点状态管理

### POST /api/workflow-status/nodes

记录节点初始状态（工作流初始化时调用）

**认证**: 需要

**请求体**:
```json
{
  "node_id": "node-001",
  "instance_id": "instance-001",
  "project_id": "project-001",
  "node_type": "app",
  "k8s_resource_name": "deployment-name",
  "k8s_resource_type": "Deployment",
  "initial_status": "Pending",
  "init_logs": "初始化日志..."
}
```

**响应**:
```json
{
  "success": true,
  "node_id": "node-001"
}
```

---

### POST /api/workflow-status/nodes/{node_id}/sync

同步单个节点状态（从K8S获取实际状态）

**认证**: 需要

**路径参数**:
- `node_id`: 节点ID

**请求体**:
```json
{
  "project_id": "project-001",
  "instance_id": "instance-001",
  "node_type": "app",
  "k8s_resource_name": "deployment-name",
  "timeout_seconds": 3600
}
```

**响应**:
```json
{
  "node_id": "node-001",
  "status": "Ready",
  "message": "Deployment is ready",
  "started_at": "2024-01-01T00:00:00",
  "finished_at": null
}
```

---

### GET /api/workflow-status/nodes/{node_id}

获取节点状态详情

**认证**: 需要

**路径参数**:
- `node_id`: 节点ID

**查询参数**:
- `project_id` (必填): 项目ID

**响应**:
```json
{
  "node": {
    "id": "record-uuid",
    "node_id": "node-001",
    "instance_id": "instance-001",
    "project_id": "project-001",
    "node_type": "app",
    "k8s_resource_name": "deployment-name",
    "k8s_resource_type": "Deployment",
    "status": "Ready",
    "started_at": "2024-01-01T00:00:00",
    "finished_at": null,
    "duration_seconds": null,
    "message": "Deployment is ready",
    "metadata": {},
    "created_at": "2024-01-01T00:00:00",
    "updated_at": "2024-01-01T00:30:00"
  }
}
```

---

### PUT /api/workflow-status/nodes/{node_id}

更新节点状态（手动更新，如停止操作）

**认证**: 需要

**路径参数**:
- `node_id`: 节点ID

**请求体**:
```json
{
  "status": "Pending",
  "message": "Node stopped by user"
}
```

**响应**:
```json
{
  "success": true,
  "node_id": "node-001",
  "status": "Pending"
}
```

---

### GET /api/workflow-status/nodes/{node_id}/logs

获取节点实时日志（从K8S Pod获取）

**认证**: 需要

**路径参数**:
- `node_id`: 节点ID

**查询参数**:
- `project_id` (必填): 项目ID
- `tail_lines` (可选): 返回日志行数，默认100，最大10000
- `container` (可选): 容器名称

**响应**:
```json
{
  "node_id": "node-001",
  "logs": "2024-01-01 00:00:00 Starting...\n2024-01-01 00:30:00 Completed",
  "pod_name": "deployment-name-abc123-xyz"
}
```

---

### GET /api/workflow-status/nodes/{node_id}/logs/stored

获取节点存储的日志（数据库中保存的日志）

**认证**: 需要

**路径参数**:
- `node_id`: 节点ID

**响应**:
```json
{
  "node_id": "node-001",
  "init_logs": "初始化日志内容...",
  "execution_logs": "执行日志内容...",
  "log_updated_at": "2024-01-01T00:30:00"
}
```

---

### POST /api/workflow-status/nodes/{node_id}/logs/init

保存节点初始化日志

**认证**: 需要

**路径参数**:
- `node_id`: 节点ID

**请求体**:
```json
{
  "logs": "初始化日志内容..."
}
```

**响应**:
```json
{
  "success": true,
  "node_id": "node-001"
}
```

---

### POST /api/workflow-status/nodes/{node_id}/logs/execution

保存节点执行日志

**认证**: 需要

**路径参数**:
- `node_id`: 节点ID

**请求体**:
```json
{
  "logs": "执行日志内容..."
}
```

**响应**:
```json
{
  "success": true,
  "node_id": "node-001"
}
```

---

### GET /api/workflow-status/nodes/{node_id}/history

获取节点状态变更历史

**认证**: 需要

**路径参数**:
- `node_id`: 节点ID

**查询参数**:
- `project_id` (必填): 项目ID

**响应**:
```json
{
  "node_id": "node-001",
  "project_id": "project-001",
  "history": [
    {
      "id": 1,
      "node_id": "node-001",
      "instance_id": "instance-001",
      "project_id": "project-001",
      "from_status": null,
      "to_status": "Pending",
      "reason": "Node initialized",
      "operator": "system",
      "created_at": "2024-01-01T00:00:00"
    },
    {
      "id": 2,
      "node_id": "node-001",
      "instance_id": "instance-001",
      "project_id": "project-001",
      "from_status": "Pending",
      "to_status": "Not_ready",
      "reason": "Running but not ready (0/1)",
      "operator": "system",
      "created_at": "2024-01-01T00:05:00"
    },
    {
      "id": 3,
      "node_id": "node-001",
      "instance_id": "instance-001",
      "project_id": "project-001",
      "from_status": "Not_ready",
      "to_status": "Ready",
      "reason": "Deployment is ready",
      "operator": "system",
      "created_at": "2024-01-01T00:10:00"
    }
  ]
}
```

---

## 工作流实例状态管理

### POST /api/workflow-status/instances/{instance_id}/sync-all

批量同步工作流所有节点状态

**认证**: 需要

**路径参数**:
- `instance_id`: 工作流实例ID

**请求体**:
```json
{
  "project_id": "project-001",
  "nodes": [
    {
      "node_id": "node-001",
      "node_type": "app",
      "k8s_resource_name": "app-deployment",
      "timeout_seconds": null
    },
    {
      "node_id": "node-002",
      "node_type": "job",
      "k8s_resource_name": "data-job",
      "timeout_seconds": 3600
    }
  ]
}
```

**响应**:
```json
{
  "instance_id": "instance-001",
  "workflow_status": {
    "status": "Running",
    "message": "Workflow running: 1 node(s) executing"
  },
  "nodes": [
    {
      "id": "record-uuid-1",
      "node_id": "node-001",
      "instance_id": "instance-001",
      "project_id": "project-001",
      "node_type": "app",
      "status": "Ready",
      "message": "Deployment is ready",
      ...
    },
    {
      "id": "record-uuid-2",
      "node_id": "node-002",
      "instance_id": "instance-001",
      "project_id": "project-001",
      "node_type": "job",
      "status": "Running",
      "message": "Job is running",
      ...
    }
  ]
}
```

---

### GET /api/workflow-status/instances/{instance_id}

获取工作流实例状态

**认证**: 需要

**路径参数**:
- `instance_id`: 工作流实例ID

**查询参数**:
- `project_id` (必填): 项目ID

**响应**:
```json
{
  "workflow": {
    "id": "record-uuid",
    "instance_id": "instance-001",
    "project_id": "project-001",
    "status": "Succeeded",
    "started_at": "2024-01-01T00:00:00",
    "finished_at": "2024-01-01T01:00:00",
    "duration_seconds": 3600,
    "message": "All nodes completed successfully",
    "total_nodes": 5,
    "pending_nodes": 0,
    "not_ready_nodes": 0,
    "ready_nodes": 2,
    "running_nodes": 0,
    "succeeded_nodes": 3,
    "failed_nodes": 0,
    "stopped_nodes": 0,
    "created_at": "2024-01-01T00:00:00",
    "updated_at": "2024-01-01T01:00:00"
  }
}
```

---

### GET /api/workflow-status/instances/{instance_id}/nodes

获取工作流所有节点状态

**认证**: 需要

**路径参数**:
- `instance_id`: 工作流实例ID

**查询参数**:
- `project_id` (必填): 项目ID

**响应**:
```json
{
  "total": 5,
  "nodes": [
    {
      "id": "record-uuid-1",
      "node_id": "node-001",
      "instance_id": "instance-001",
      "project_id": "project-001",
      "node_type": "app",
      "status": "Ready",
      ...
    },
    {
      "id": "record-uuid-2",
      "node_id": "node-002",
      "instance_id": "instance-001",
      "project_id": "project-001",
      "node_type": "job",
      "status": "Succeeded",
      ...
    }
  ]
}
```

---

### GET /api/workflow-status/instances/{instance_id}/history

获取工作流状态变更历史（所有节点的状态变更）

**认证**: 需要

**路径参数**:
- `instance_id`: 工作流实例ID

**查询参数**:
- `project_id` (必填): 项目ID

**响应**:
```json
{
  "instance_id": "instance-001",
  "project_id": "project-001",
  "history": [
    {
      "id": 1,
      "node_id": "node-001",
      "instance_id": "instance-001",
      "project_id": "project-001",
      "from_status": null,
      "to_status": "Pending",
      "reason": "Node initialized",
      "operator": "system",
      "created_at": "2024-01-01T00:00:00"
    },
    ...
  ]
}
```

---

### GET /api/workflow-status/instances

获取工作流状态列表

**认证**: 需要

**查询参数**:
- `project_id` (必填): 项目ID
- `status` (可选): 状态筛选 (Pending, Running, Succeeded, Failed)
- `page` (可选): 页码，默认1
- `page_size` (可选): 每页数量，默认20，最大100

**响应**:
```json
{
  "total": 50,
  "page": 1,
  "page_size": 20,
  "workflows": [
    {
      "id": "record-uuid",
      "instance_id": "instance-001",
      "project_id": "project-001",
      "status": "Succeeded",
      "message": "All nodes completed successfully",
      "total_nodes": 5,
      "created_at": "2024-01-01T00:00:00",
      "updated_at": "2024-01-01T01:00:00"
    },
    ...
  ]
}
```

---

## 统计信息

### GET /api/workflow-status/statistics

获取状态统计信息

**认证**: 需要

**查询参数**:
- `project_id` (必填): 项目ID
- `start_time` (可选): 统计开始时间 (ISO格式)
- `end_time` (可选): 统计结束时间 (ISO格式)

**响应**:
```json
{
  "project_id": "project-001",
  "workflows": {
    "total": 100,
    "pending": 5,
    "running": 10,
    "succeeded": 80,
    "failed": 5,
    "not_ready": 0,
    "ready": 0,
    "stopped": 0
  },
  "nodes": {
    "total": 500,
    "pending": 20,
    "running": 30,
    "succeeded": 400,
    "failed": 45,
    "not_ready": 5,
    "ready": 0,
    "stopped": 0
  },
  "period_start": "2024-01-01T00:00:00",
  "period_end": "2024-01-31T23:59:59"
}
```

---

## 错误码说明

| 错误码 | HTTP状态码 | 说明 |
|--------|-----------|------|
| NOT_FOUND | 404 | 资源不存在 |
| FORBIDDEN | 403 | 无权限访问 |
| UNAUTHORIZED | 401 | 未认证 |
| VALIDATION_ERROR | 422 | 参数验证错误 |
| INTERNAL_ERROR | 500 | 内部错误 |

---

## 使用示例

### Python示例

```python
import httpx

BASE_URL = "http://localhost:10007/api/workflow-status"

async def record_node(node_id: str, instance_id: str, project_id: str, node_type: str, k8s_name: str):
    """记录节点初始状态"""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BASE_URL}/nodes",
            json={
                "node_id": node_id,
                "instance_id": instance_id,
                "project_id": project_id,
                "node_type": node_type,
                "k8s_resource_name": k8s_name,
                "initial_status": "Pending"
            }
        )
        return response.json()

async def sync_all_nodes(instance_id: str, project_id: str, nodes: list):
    """批量同步节点状态"""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BASE_URL}/instances/{instance_id}/sync-all",
            json={
                "project_id": project_id,
                "nodes": nodes
            }
        )
        return response.json()

async def get_workflow_status(instance_id: str, project_id: str):
    """获取工作流状态"""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{BASE_URL}/instances/{instance_id}",
            params={"project_id": project_id}
        )
        return response.json()
```

### cURL示例

```bash
# 记录节点初始状态
curl -X POST "http://localhost:10007/api/workflow-status/nodes" \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": "node-001",
    "instance_id": "instance-001",
    "project_id": "project-001",
    "node_type": "app",
    "k8s_resource_name": "my-deployment",
    "initial_status": "Pending"
  }'

# 同步节点状态
curl -X POST "http://localhost:10007/api/workflow-status/nodes/node-001/sync" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "project-001",
    "instance_id": "instance-001",
    "node_type": "app",
    "k8s_resource_name": "my-deployment"
  }'

# 获取工作流状态
curl "http://localhost:10007/api/workflow-status/instances/instance-001?project_id=project-001"

# 获取节点日志
curl "http://localhost:10007/api/workflow-status/nodes/node-001/logs?project_id=project-001&tail_lines=100"
```
