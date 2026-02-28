# SecFlow Workflow Service API 概述

## Base URL

```
http://<host>:<port>/api/workflow
```

## Service Port

- 默认端口: `10005`

## Authentication

所有API需要在Authorization头中携带Bearer token:

```
Authorization: Bearer <token>
```

Token由认证服务验证。触发端点 `/trigger/{instance_id}` 可无认证调用。

---

## API 模块索引

| 模块 | 文档 | 描述 |
|------|------|------|
| 应用模板 | [API-AppTemplate.md](API-AppTemplate.md) | 管理持久化应用模板 (Deployment) |
| 任务模板 | [API-JobTemplate.md](API-JobTemplate.md) | 管理一次性任务模板 (Job) |
| 工作流实例 | [API-WorkflowInstance.md](API-WorkflowInstance.md) | 工作流生命周期管理 |
| 工作流节点 | [API-WorkflowNode.md](API-WorkflowNode.md) | 工作流节点管理 |
| 触发器 | [API-Trigger.md](API-Trigger.md) | HTTP触发工作流 |
| 健康检查 | [API-Health.md](API-Health.md) | 服务健康状态 |

---

## Common Parameters

### Path Parameters

| 参数 | 类型 | 描述 |
|------|------|------|
| `template_id` | string | 应用模板或任务模板ID（系统自动生成） |
| `instance_id` | string | 工作流实例ID（系统自动生成） |
| `node_id` | string | 工作流节点ID（系统自动生成） |

### Query Parameters

| 参数 | 类型 | 描述 |
|------|------|------|
| `project_id` | string | 项目ID |
| `scope` | string | 模板范围: `global` 或 `project` |
| `status` | string | 状态过滤: `pending`, `running`, `succeeded`, `failed`, `stopped` |

---

## Enumerations

### Template Scope

| 值 | 描述 |
|------|------|
| `global` | 全局模板所有项目可见 |
| `project` | 项目级模板仅在项目内可见 |

### Image Pull Policy

| 值 | 描述 |
|------|------|
| `Always` | 总是拉取镜像 |
| `IfNotPresent` | 仅当不存在时拉取 |
| `Never` | 从不拉取 |

### Service Type

| 值 | 描述 |
|------|------|
| `ClusterIP` | 集群内部服务 (默认) |
| `LoadBalancer` | 负载均衡器类型 |
| `NodePort` | 节点端口类型 |

### Workflow Status

| 值 | 描述 |
|------|------|
| `pending` | 待执行 |
| `running` | 运行中 |
| `succeeded` | 成功 |
| `failed` | 失败 |
| `stopped` | 已停止 |

### Node Type

| 值 | 描述 |
|------|------|
| `app` | Deployment应用 |
| `job` | 一次性Job |

### Node Status

| 值 | 描述 |
|------|------|
| `pending` | 待执行 |
| `running` | 运行中 |
| `succeeded` | 成功 |
| `failed` | 失败 |
| `stopped` | 已停止 |

**注意：**
- 应用模板(app): Deployment就绪时节点状态变为 `succeeded`（就绪=成功），不再保持 `running`
- 任务模板(job): 状态与K8S Job状态保持一致

### Run Mode

| 值 | 描述 |
|------|------|
| `once` | 一次性运行工作流执行一次后结束 |
| `persistent` | 持久化运行工作流持续有效可被多次触发 |

### Trigger Type

| 值 | 描述 |
|------|------|
| `manual` | 手动触发仅可通过API启动 |
| `http` | HTTP触发可通过HTTP请求触发工作流 |

---

## Common Response Schemas

### SuccessResponse

```json
{
  "message": "string"
}
```

### ErrorResponse

```json
{
  "code": "string",
  "message": "string",
  "details": {}
}
```

### HealthResponse

```json
{
  "status": "string",
  "service": "string"
}
```

---

## Error Codes

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

## ID 生成规则

所有资源的ID由系统自动生成，用户创建时**不需要也不允许**指定ID：

| 资源类型 | ID格式示例 | 说明 |
|----------|------------|------|
| 应用模板 | `wf-tmpl-xxx-abc123` | 基于名称生成 |
| 任务模板 | `wf-tmpl-xxx-def456` | 基于名称生成 |
| 工作流实例 | `wf-inst-xxx-jkl012` | 基于名称生成 |
| 工作流节点 | `wf-node-xxx-mno345` | 基于实例ID和节点名称生成 |

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

## Database Tables

| Table Name | Description |
|-----------|-------------|
| secflow_platform_workflow_app_template | 应用模板 |
| secflow_platform_workflow_job_template | 任务模板 |
| secflow_platform_workflow_workflow_instance | 工作流实例 |
| secflow_platform_workflow_workflow_node_instance | 工作流节点实例 |
