# SecFlow K8S 资源管理服务 API 手册

## API 汇总

| 模块 | 方法 | 端点 | 功能 | 认证 |
|------|------|------|------|------|
| **健康检查** | GET | `/api/k8s/health` | 服务健康检查 | 否 |
| **就绪检查** | GET | `/api/k8s/ready` | 服务就绪检查 | 否 |
| **Namespace** | GET | `/api/k8s/namespaces/{namespace_name}` | 检查Namespace是否存在 | 是 |
| **项目Namespace** | GET | `/api/k8s/projects/{project_id}/namespace` | 获取项目Namespace信息 | 是 |
| **项目资源** | GET | `/api/k8s/projects/{project_id}/resources` | 获取项目资源概览 | 是 |
| **Pod** | GET | `/api/k8s/pods` | 获取Pod列表 | 是 |
| | GET | `/api/k8s/pods/{pod_name}` | 获取Pod详情 | 是 |
| | GET | `/api/k8s/pods/{pod_name}/containers` | 获取Pod容器列表 | 是 |
| | POST | `/api/k8s/pods` | 创建Pod | 是 |
| | DELETE | `/api/k8s/pods/{pod_name}` | 删除Pod | 是 |
| | GET | `/api/k8s/pods/{pod_name}/logs` | 获取Pod日志 | 是 |
| **Pod交互** | WS | `/api/k8s/ws/pods/{pod_name}/exec` | WebSocket Exec交互 | 是 |
| | WS | `/api/k8s/ws/pods/{pod_name}/attach` | WebSocket Attach交互 | 是 |
| **Service** | GET | `/api/k8s/services` | 获取Service列表 | 是 |
| | GET | `/api/k8s/services/{service_name}` | 获取Service详情 | 是 |
| | POST | `/api/k8s/services` | 创建Service | 是 |
| | DELETE | `/api/k8s/services/{service_name}` | 删除Service | 是 |
| **Ingress** | GET | `/api/k8s/ingresses` | 获取Ingress列表 | 是 |
| | GET | `/api/k8s/ingresses/{ingress_name}` | 获取Ingress详情 | 是 |
| | POST | `/api/k8s/ingresses` | 创建Ingress | 是 |
| | DELETE | `/api/k8s/ingresses/{ingress_name}` | 删除Ingress | 是 |
| **Secret** | GET | `/api/k8s/secrets` | 获取Secret列表 | 是 |
| | GET | `/api/k8s/secrets/{secret_name}` | 获取Secret详情 | 是 |
| | POST | `/api/k8s/secrets` | 创建Secret | 是 |
| | DELETE | `/api/k8s/secrets/{secret_name}` | 删除Secret | 是 |
| **ConfigMap** | GET | `/api/k8s/configmaps` | 获取ConfigMap列表 | 是 |
| | GET | `/api/k8s/configmaps/{configmap_name}` | 获取ConfigMap详情 | 是 |
| | POST | `/api/k8s/configmaps` | 创建ConfigMap | 是 |
| | DELETE | `/api/k8s/configmaps/{configmap_name}` | 删除ConfigMap | 是 |
| **Deployment** | GET | `/api/k8s/deployments` | 获取Deployment列表 | 是 |
| | GET | `/api/k8s/deployments/{deployment_name}` | 获取Deployment详情 | 是 |
| | POST | `/api/k8s/deployments` | 创建Deployment | 是 |
| | DELETE | `/api/k8s/deployments/{deployment_name}` | 删除Deployment | 是 |
| | POST | `/api/k8s/deployments/{deployment_name}/scale` | 扩缩容Deployment | 是 |
| **StatefulSet** | GET | `/api/k8s/statefulsets` | 获取StatefulSet列表 | 是 |
| | GET | `/api/k8s/statefulsets/{statefulset_name}` | 获取StatefulSet详情 | 是 |
| | POST | `/api/k8s/statefulsets` | 创建StatefulSet | 是 |
| | DELETE | `/api/k8s/statefulsets/{statefulset_name}` | 删除StatefulSet | 是 |
| **DaemonSet** | GET | `/api/k8s/daemonsets` | 获取DaemonSet列表 | 是 |
| | GET | `/api/k8s/daemonsets/{daemonset_name}` | 获取DaemonSet详情 | 是 |
| | POST | `/api/k8s/daemonsets` | 创建DaemonSet | 是 |
| | DELETE | `/api/k8s/daemonsets/{daemonset_name}` | 删除DaemonSet | 是 |
| **Job** | GET | `/api/k8s/jobs` | 获取Job列表 | 是 |
| | GET | `/api/k8s/jobs/{job_name}` | 获取Job详情 | 是 |
| | POST | `/api/k8s/jobs` | 创建Job | 是 |
| | DELETE | `/api/k8s/jobs/{job_name}` | 删除Job | 是 |
| **PVC** | GET | `/api/k8s/pvcs` | 获取PVC列表 | 是 |
| | GET | `/api/k8s/pvcs/{pvc_name}` | 获取PVC详情 | 是 |
| | POST | `/api/k8s/pvcs` | 创建PVC | 是 |
| | DELETE | `/api/k8s/pvcs/{pvc_name}` | 删除PVC | 是 |

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
GET /api/k8s/pods?project_id=xxx
```

系统会通过 project_id 从数据库查询对应的 K8S Namespace，而不是直接使用前端传递的 namespace，确保安全。

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

## 健康检查

### GET /api/k8s/health

服务健康检查

**参数**: 无

**响应**:
```json
{
  "status": "healthy"
}
```

---

### GET /api/k8s/ready

服务就绪检查

**参数**: 无

**响应**:
```json
{
  "status": "ready"
}
```

---

## Namespace 管理

### GET /api/k8s/namespaces/{namespace_name}

检查Namespace是否存在

**参数**:
- `namespace_name` (path): Namespace名称

**认证**: 需要

**响应**:
```json
{
  "exists": true,
  "name": "secflow-xxx",
  "status": "Active"
}
```

如果Namespace不存在:
```json
{
  "exists": false,
  "name": "secflow-xxx",
  "status": "NotFound"
}
```

---

### GET /api/k8s/projects/{project_id}/namespace

获取项目Namespace信息

**参数**:
- `project_id` (path): 项目ID

**认证**: 需要

**响应**:
```json
{
  "project_id": "xxx",
  "namespace": "secflow-xxx",
  "exists": true,
  "status": "Active"
}
```

---

## 项目资源

### GET /api/k8s/projects/{project_id}/resources

获取项目下所有K8S资源概览

**参数**:
- `project_id` (路径): 项目ID

**认证**: 需要

**响应**:
```json
{
  "project_id": "xxx",
  "namespace": "secflow-xxx",
  "pods": 5,
  "services": 3,
  "deployments": 2,
  "statefulsets": 0,
  "daemonsets": 0,
  "jobs": 1,
  "configmaps": 2,
  "secrets": 1,
  "ingresses": 1,
  "pvcs": 1
}
```

---

## Pod 管理

### GET /api/k8s/pods

获取Pod列表

**参数**:
- `project_id` (query): 项目ID
- `label_selector` (query, optional): 标签选择器

**认证**: 需要

**响应**:
```json
{
  "total": 5,
  "items": [
    {
      "name": "my-pod-xxx",
      "namespace": "secflow-xxx",
      "label": { "app": "myapp" },
      "annotation": {},
      "status": "Running",
      "node_name": "worker-node-1",
      "service_account": "default",
      "container": [...],
      "created_at": "2024-01-01T00:00:00"
    }
  ]
}
```

---

### GET /api/k8s/pods/{pod_name}

获取Pod详情

**参数**:
- `pod_name` (path): Pod名称
- `project_id` (query): 项目ID

**认证**: 需要

---

### GET /api/k8s/pods/{pod_name}/containers

获取Pod容器列表

**参数**:
- `pod_name` (path): Pod名称
- `project_id` (query): 项目ID

**认证**: 需要

**响应**:
```json
{
  "pod_name": "my-pod",
  "containers": [
    {
      "name": "main-container",
      "image": "nginx:latest",
      "image_pull_policy": "IfNotPresent",
      "ports": [{ "containerPort": 80, "protocol": "TCP" }],
      "command": null,
      "args": null
    }
  ]
}
```

---

### POST /api/k8s/pods

创建Pod

**参数**:
- `project_id` (query): 项目ID
- `manifest` (body): Pod Manifest

**认证**: 需要

**请求体**:
```json
{
  "metadata": {
    "name": "my-pod",
    "namespace": "secflow-xxx",
    "labels": { "app": "myapp" }
  },
  "spec": {
    "containers": [
      {
        "name": "main",
        "image": "nginx:latest"
      }
    ]
  }
}
```

---

### DELETE /api/k8s/pods/{pod_name}

删除Pod

**参数**:
- `pod_name` (path): Pod名称
- `project_id` (query): 项目ID

**认证**: 需要

---

### GET /api/k8s/pods/{pod_name}/logs

获取Pod日志

**参数**:
- `pod_name` (path): Pod名称
- `project_id` (query): 项目ID
- `container` (query, optional): 容器名称
- `tail_lines` (query, optional): 日志行数，默认100
- `previous` (query, optional): 是否获取前一个容器的日志

**认证**: 需要

**响应**:
```json
{
  "logs": "2024-01-01 00:00:00 Starting application..."
}
```

---

## Pod 实时交互 (WebSocket)

### WebSocket /api/k8s/ws/pods/{pod_name}/exec

WebSocket Exec - 类似 kubectl exec -it 的能力

在Pod中执行新命令并进行实时交互

**参数**:
- `pod_name` (path): Pod名称
- `project_id` (query): 项目ID
- `container` (query, optional): 容器名称
- `command` (query, optional): 执行的命令默认 `/bin/sh`

**认证**: 需要

**使用方式**:
```javascript
// 前端连接示例
const ws = new WebSocket('ws://host:port/api/k8s/ws/pods/my-pod/exec?project_id=xxx&command=/bin/sh');

// 接收输出
ws.onmessage = (event) => {
    console.log('output:', event.data);
};

// 发送命令
ws.send('ls -la\n');

// 退出
ws.send('exit');
ws.close();
```

---

### WebSocket /api/k8s/ws/pods/{pod_name}/attach

WebSocket Attach - 类似 kubectl attach 的能力

附加到运行中的容器并进行实时交互

**参数**:
- `pod_name` (path): Pod名称
- `project_id` (query): 项目ID
- `container` (query, optional): 容器名称

**认证**: 需要

**使用方式**:
```javascript
const ws = new WebSocket('ws://host:port/api/k8s/ws/pods/my-pod/attach?project_id=xxx');

// 接收输出
ws.onmessage = (event) => {
    console.log(event.data);
};

// 发送输入
ws.send('any input');

// 退出
ws.send('exit');
ws.close();
```

---

## Service 管理

### GET /api/k8s/services

获取Service列表

**参数**:
- `project_id` (query): 项目ID
- `label_selector` (query, optional): 标签选择器

**认证**: 需要

---

### GET /api/k8s/services/{service_name}

获取Service详情

---

### POST /api/k8s/services

创建Service

**请求体**:
```json
{
  "name": "my-service",
  "type": "ClusterIP",
  "selector": { "app": "myapp" },
  "ports": [
    { "name": "http", "port": 80, "target_port": 8080 }
  ]
}
```

---

### DELETE /api/k8s/services/{service_name}

删除Service

---

## Ingress 管理

### GET /api/k8s/ingresses

获取Ingress列表

### GET /api/k8s/ingresses/{ingress_name}

获取Ingress详情

### POST /api/k8s/ingresses

创建Ingress

**请求体**:
```json
{
  "name": "my-ingress",
  "ingress_class_name": "nginx",
  "annotation": {},
  "tls": [],
  "rule": {
    "host": "example.com",
    "paths": [
      {
        "path": "/",
        "path_type": "Prefix",
        "backend": {
          "service": {
            "name": "my-service",
            "port": { "number": 80 }
          }
        }
      }
    ]
  }
}
```

### DELETE /api/k8s/ingresses/{ingress_name}

删除Ingress

---

## Secret 管理

### GET /api/k8s/secrets

获取Secret列表

### GET /api/k8s/secrets/{secret_name}

获取Secret详情

### POST /api/k8s/secrets

创建Secret

**请求体**:
```json
{
  "name": "my-secret",
  "type": "Opaque",
  "data": {
    "key": "dmFsdWU="
  },
  "label": {},
  "annotation": {}
}
```

### DELETE /api/k8s/secrets/{secret_name}

删除Secret

---

## ConfigMap 管理

### GET /api/k8s/configmaps

获取ConfigMap列表

### GET /api/k8s/configmaps/{configmap_name}

获取ConfigMap详情

### POST /api/k8s/configmaps

创建ConfigMap

**请求体**:
```json
{
  "name": "my-configmap",
  "data": {
    "config.json": "{ \"key\": \"value\" }"
  },
  "binary_data": {},
  "label": {},
  "annotation": {}
}
```

### DELETE /api/k8s/configmaps/{configmap_name}

删除ConfigMap

---

## Deployment 管理

### GET /api/k8s/deployments

获取Deployment列表

### GET /api/k8s/deployments/{deployment_name}

获取Deployment详情

### POST /api/k8s/deployments

创建Deployment

**请求体**:
```json
{
  "manifest": {
    "metadata": {
      "name": "my-deployment"
    },
    "spec": {
      "replicas": 3,
      "selector": { "matchLabels": { "app": "myapp" } },
      "template": {
        "spec": {
          "containers": [
            {
              "name": "main",
              "image": "nginx:latest"
            }
          ]
        }
      }
    }
  }
}
```

### DELETE /api/k8s/deployments/{deployment_name}

删除Deployment

### POST /api/k8s/deployments/{deployment_name}/scale

扩缩容Deployment

**请求体**:
```json
{
  "replica": 5
}
```

---

## StatefulSet 管理

### GET /api/k8s/statefulsets

获取StatefulSet列表

### GET /api/k8s/statefulsets/{statefulset_name}

获取StatefulSet详情

### POST /api/k8s/statefulsets

创建StatefulSet

**请求体**:
```json
{
  "manifest": {
    "metadata": { "name": "my-sts" },
    "spec": {
      "serviceName": "my-sts",
      "replica": 3,
      "selector": { "matchLabels": { "app": "myapp" } },
      "template": { "spec": { "containers": [...] } }
    }
  }
}
```

### DELETE /api/k8s/statefulsets/{statefulset_name}

删除StatefulSet

---

## DaemonSet 管理

### GET /api/k8s/daemonsets

获取DaemonSet列表

### GET /api/k8s/daemonsets/{daemonset_name}

获取DaemonSet详情

### POST /api/k8s/daemonsets

创建DaemonSet

### DELETE /api/k8s/daemonsets/{daemonset_name}

删除DaemonSet

---

## Job 管理

### GET /api/k8s/jobs

获取Job列表

### GET /api/k8s/jobs/{job_name}

获取Job详情

### POST /api/k8s/jobs

创建Job

### DELETE /api/k8s/jobs/{job_name}

删除Job

---

## PVC 管理

### GET /api/k8s/pvcs

获取PVC列表

### GET /api/k8s/pvcs/{pvc_name}

获取PVC详情

### POST /api/k8s/pvcs

创建PVC

**请求体**:
```json
{
  "manifest": {
    "metadata": { "name": "my-pvc" },
    "spec": {
      "accessMode": ["ReadWriteOnce"],
      "storageClassName": "standard",
      "resources": {
        "requests": { "storage": "1Gi" }
      }
    }
  }
}
```

### DELETE /api/k8s/pvcs/{pvc_name}

删除PVC

---

## 错误码说明

| 错误码 | 说明 |
|--------|------|
| NOT_FOUND | 资源不存在 |
| FORBIDDEN | 无权限访问 |
| UNAUTHORIZED | 未认证 |
| VALIDATION_ERROR | 参数验证错误 |
| CONFLICT | 资源冲突 |
| INTERNAL_ERROR | 内部错误 |