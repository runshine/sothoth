# SecFlow 工作流状态管理服务使用指南

## 概述

`secflow-platform-workflow-status` 是一个独立的微服务，负责管理工作流节点的状态。它提供以下核心功能：

1. **节点状态管理**: 记录、查询、同步节点的实时状态
2. **状态历史追踪**: 记录节点状态变更历史
3. **日志管理**: 存储和查询节点执行日志
4. **工作流状态聚合**: 根据节点状态计算工作流整体状态

---

## 快速开始

### 1. 服务配置

```yaml
# config.yaml
database:
  host: "172.31.30.100"
  port: 3306
  username: "secflow"
  password: "password"
  name: "secflow"
  pool_size: 10
  max_overflow: 20

k8s_service:
  enabled: true
  host: "127.0.0.1"
  port: 8080
  timeout: 30

app:
  host: "0.0.0.0"
  port: 10007
```

### 2. 启动服务

```bash
cd secflow-platform-workflow-status
python start.py
```

服务将在端口 10007 启动。

---

## 节点状态说明

### APP节点状态

APP节点对应Kubernetes的Deployment资源。

```
┌─────────────────────────────────────────────────────────────┐
│                      APP节点状态流转                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────┐     Pod启动      ┌───────────┐    就绪检查通过  ┌──────┐
│   │ Pending │ ──────────────► │ Not_ready │ ─────────────► │ Ready │
│   └─────────┘                  └───────────┘                └──────┘
│       ↑                              │                          │
│       │                              │                          │
│       │         Pod重启/失败         │                          │
│       └──────────────────────────────┘                          │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

| 状态 | 条件 | 说明 |
|------|------|------|
| Pending | `ready_replicas == 0` | Pod未运行，等待启动 |
| Not_ready | `0 < ready_replicas < replicas` | Pod已运行但未全部就绪 |
| Ready | `ready_replicas >= replicas > 0` | 所有Pod就绪，服务可用 |

### JOB节点状态

JOB节点对应Kubernetes的Job资源。

```
┌─────────────────────────────────────────────────────────────┐
│                      JOB节点状态流转                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────┐    Job启动    ┌─────────┐                     │
│   │ Pending │ ────────────► │ Running │                     │
│   └─────────┘               └────┬────┘                     │
│                                  │                           │
│                    ┌─────────────┴─────────────┐            │
│                    │                           │            │
│                    ▼                           ▼            │
│            ┌───────────┐               ┌────────┐           │
│            │ Succeeded │               │ Failed │           │
│            └───────────┘               └────────┘           │
│              (终态)                      (终态)              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

| 状态 | 条件 | 说明 |
|------|------|------|
| Pending | Job未开始执行 | 等待调度 |
| Running | Job正在执行 | Pod运行中 |
| Succeeded | `job.status == Succeeded` | 执行成功（终态） |
| Failed | `job.status == Failed` 或超时 | 执行失败（终态） |

---

## 典型使用场景

### 场景1: 工作流启动时初始化节点状态

当workflow模块启动工作流时，需要为每个节点创建初始状态记录。

```python
# workflow模块中的调用示例
from app.services.workflow_status_client import get_workflow_status_client

async def initialize_workflow_nodes(instance_id: str, project_id: str, nodes: list):
    """初始化工作流节点状态"""
    client = get_workflow_status_client()

    for node in nodes:
        await client.record_node(
            node_id=node["node_id"],
            instance_id=instance_id,
            project_id=project_id,
            node_type=node["type"],  # "app" 或 "job"
            k8s_resource_name=node["k8s_name"],
            initial_status="Pending"
        )
```

### 场景2: 定期同步节点状态

workflow模块可以定期调用状态同步接口，获取节点最新状态。

```python
import asyncio

async def sync_workflow_status(instance_id: str, project_id: str, nodes: list):
    """同步工作流所有节点状态"""
    client = get_workflow_status_client()

    # 构建节点列表
    node_list = [
        {
            "node_id": node["node_id"],
            "node_type": node["type"],
            "k8s_resource_name": node["k8s_name"],
            "timeout_seconds": node.get("timeout")
        }
        for node in nodes
    ]

    # 批量同步
    result = await client.sync_all_nodes(
        instance_id=instance_id,
        project_id=project_id,
        nodes=node_list
    )

    return result
```

### 场景3: 查询节点状态和日志

```python
async def get_node_status_and_logs(node_id: str, project_id: str):
    """获取节点状态和日志"""
    client = get_workflow_status_client()

    # 获取节点状态
    status = await client.get_node_status(node_id, project_id)

    # 获取实时日志（从K8S Pod）
    logs = await client.get_node_logs(node_id, project_id, tail_lines=500)

    # 获取存储的日志（数据库中保存的）
    stored_logs = await client.get_stored_logs(node_id)

    return {
        "status": status,
        "realtime_logs": logs,
        "stored_logs": stored_logs
    }
```

### 场景4: 保存初始化日志

当节点初始化过程中产生日志时，可以保存到状态服务。

```python
async def save_node_init_logs(node_id: str, logs: str):
    """保存节点初始化日志"""
    client = get_workflow_status_client()
    await client.save_init_logs(node_id, logs)
```

---

## 工作流集成流程

以下是workflow模块与workflow-status模块的完整集成流程：

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           工作流执行流程                                       │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. 用户触发工作流                                                            │
│     │                                                                        │
│     ▼                                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ workflow模块                                                         │    │
│  │                                                                      │    │
│  │  2. 生成 instance_id (工作流执行ID)                                   │    │
│  │  3. 解析工作流配置，获取所有节点信息                                    │    │
│  │                                                                      │    │
│  └──────────────────────────────┬──────────────────────────────────────┘    │
│                                 │                                            │
│                                 ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ workflow → workflow-status                                           │    │
│  │                                                                      │    │
│  │  4. 调用 POST /nodes 为每个节点记录初始状态                            │    │
│  │     - node_id, instance_id, project_id                               │    │
│  │     - node_type (app/job)                                            │    │
│  │     - k8s_resource_name                                              │    │
│  │     - initial_status = "Pending"                                     │    │
│  │                                                                      │    │
│  └──────────────────────────────┬──────────────────────────────────────┘    │
│                                 │                                            │
│                                 ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ workflow模块                                                         │    │
│  │                                                                      │    │
│  │  5. 调用K8S服务创建资源 (Deployment/Job)                               │    │
│  │  6. 保存初始化日志到 workflow-status                                   │    │
│  │                                                                      │    │
│  └──────────────────────────────┬──────────────────────────────────────┘    │
│                                 │                                            │
│                                 ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 定期状态同步循环                                                      │    │
│  │                                                                      │    │
│  │  7. 调用 POST /instances/{instance_id}/sync-all                       │    │
│  │     - workflow-status 从K8S获取实际状态                               │    │
│  │     - 更新数据库中的状态记录                                           │    │
│  │     - 记录状态变更历史                                                │    │
│  │     - 聚合工作流整体状态                                              │    │
│  │                                                                      │    │
│  │  8. 根据状态判断工作流是否完成                                         │    │
│  │     - 全部 Ready/Succeeded → 工作流成功                               │    │
│  │     - 有节点 Failed → 工作流失败                                       │    │
│  │                                                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## API调用示例

### 1. 记录节点初始状态

**请求:**
```bash
POST /api/workflow-status/nodes
Content-Type: application/json

{
    "node_id": "app-node-001",
    "instance_id": "wf-20240101-abc123",
    "project_id": "project-001",
    "node_type": "app",
    "k8s_resource_name": "data-processor",
    "k8s_resource_type": "Deployment",
    "initial_status": "Pending"
}
```

**响应:**
```json
{
    "success": true,
    "node_id": "app-node-001"
}
```

### 2. 批量同步节点状态

**请求:**
```bash
POST /api/workflow-status/instances/wf-20240101-abc123/sync-all
Content-Type: application/json

{
    "project_id": "project-001",
    "nodes": [
        {
            "node_id": "app-node-001",
            "node_type": "app",
            "k8s_resource_name": "data-processor"
        },
        {
            "node_id": "job-node-001",
            "node_type": "job",
            "k8s_resource_name": "data-transform-job",
            "timeout_seconds": 3600
        }
    ]
}
```

**响应:**
```json
{
    "instance_id": "wf-20240101-abc123",
    "workflow_status": {
        "status": "Running",
        "message": "Workflow running: 1 node(s) executing"
    },
    "nodes": [
        {
            "node_id": "app-node-001",
            "status": "Ready",
            "message": "Deployment is ready",
            ...
        },
        {
            "node_id": "job-node-001",
            "status": "Running",
            "message": "Job is running",
            ...
        }
    ]
}
```

### 3. 获取节点日志

**请求:**
```bash
GET /api/workflow-status/nodes/job-node-001/logs?project_id=project-001&tail_lines=200
```

**响应:**
```json
{
    "node_id": "job-node-001",
    "logs": "2024-01-01 10:00:00 Starting data transformation...\n2024-01-01 10:05:00 Processing batch 1/10\n...",
    "pod_name": "data-transform-job-abc123-xyz"
}
```

---

## 最佳实践

### 1. 工作流ID设计

使用有意义的工作流ID（instance_id），便于追溯和查询：

```python
import uuid
from datetime import datetime

def generate_instance_id(workflow_name: str = None) -> str:
    """生成工作流实例ID"""
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    unique_id = str(uuid.uuid4())[:8]
    prefix = workflow_name or "wf"
    return f"{prefix}-{timestamp}-{unique_id}"

# 示例: data-pipeline-20240101120000-abc12345
```

### 2. 状态同步频率

根据工作流类型设置合适的同步频率：

```python
# 短时任务（秒级）：高频同步
SYNC_INTERVAL_SHORT = 5  # 秒

# 常规任务（分钟级）：中频同步
SYNC_INTERVAL_NORMAL = 30  # 秒

# 长时任务（小时级）：低频同步
SYNC_INTERVAL_LONG = 60  # 秒
```

### 3. 错误处理

```python
async def safe_sync_node_status(client, node_id, project_id, instance_id, node_type, k8s_name):
    """安全的状态同步，带错误处理"""
    try:
        result = await client.sync_node_status(
            node_id=node_id,
            project_id=project_id,
            instance_id=instance_id,
            node_type=node_type,
            k8s_resource_name=k8s_name
        )
        return result
    except Exception as e:
        logger.error(f"同步节点状态失败: {node_id}, 错误: {e}")
        # 返回默认状态，不影响其他节点
        return {
            "node_id": node_id,
            "status": "Pending",
            "error": str(e)
        }
```

### 4. 日志管理

```python
# 初始化日志：保存资源配置和创建过程
init_logs = f"""
=== 节点初始化 ===
节点ID: {node_id}
类型: {node_type}
K8S资源: {k8s_name}
创建时间: {datetime.utcnow().isoformat()}
配置: {json.dumps(config, indent=2)}
"""
await client.save_init_logs(node_id, init_logs)

# 执行日志：保存运行时输出（可选，大日志建议直接查询K8S）
execution_logs = await client.get_node_logs(node_id, project_id)
# 大日志不建议保存到数据库，直接返回给前端
```

---

## 故障排查

### 问题1: 节点状态一直是Pending

**可能原因:**
1. K8S资源未创建成功
2. workflow-status无法连接K8S服务
3. K8S资源名称不匹配

**排查步骤:**
```bash
# 1. 检查K8S服务连接
curl http://localhost:8080/api/k8s/health

# 2. 检查节点状态记录
curl "http://localhost:10007/api/workflow-status/nodes/{node_id}?project_id={project_id}"

# 3. 检查状态同步结果
curl -X POST "http://localhost:10007/api/workflow-status/nodes/{node_id}/sync" \
  -H "Content-Type: application/json" \
  -d '{"project_id": "...", "instance_id": "...", "node_type": "app", "k8s_resource_name": "..."}'
```

### 问题2: 工作流状态不正确

**可能原因:**
1. 节点状态统计逻辑问题
2. 部分节点未正确记录

**排查步骤:**
```bash
# 检查工作流所有节点状态
curl "http://localhost:10007/api/workflow-status/instances/{instance_id}/nodes?project_id={project_id}"

# 检查工作流状态记录
curl "http://localhost:10007/api/workflow-status/instances/{instance_id}?project_id={project_id}"
```

### 问题3: 日志获取失败

**可能原因:**
1. Pod已删除
2. 容器名称不正确
3. K8S API权限问题

**排查步骤:**
```bash
# 检查存储的日志
curl "http://localhost:10007/api/workflow-status/nodes/{node_id}/logs/stored"

# 尝试直接获取实时日志
curl "http://localhost:10007/api/workflow-status/nodes/{node_id}/logs?project_id={project_id}&tail_lines=100"
```

---

## 性能优化建议

1. **批量同步**: 使用 `sync_all_nodes` 而非多次调用 `sync_node_status`
2. **日志存储**: 大日志不要存储到数据库，使用 `get_node_logs` 直接从K8S获取
3. **连接复用**: workflow模块应复用 `WorkflowStatusClient` 实例
4. **缓存策略**: 对于频繁查询的节点状态，可在workflow模块添加本地缓存

---

## 相关文档

- [API手册](./API.md)
- [架构设计](./ARCHITECTURE.md)
- [节点状态抽离设计](./NODE_STATUS_EXTRACTION_DESIGN.md)
