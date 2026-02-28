# 应用模板 API

管理工作流实例生命周期 (创建、运行、删除、日志)。
工作流实例中的每个节点直接引用应用模板(AppTemplate)或任务模板(JobTemplate)。
支持两种创建方式：
1. **直接创建**: 创建实例时直接指定所有节点和边
2. **先创建空白实例**: 先创建无节点的空白实例，然后通过节点API逐个添加节点

## API 列表

| 方法 | 端点 | 描述 |
|------|------|------|
| POST | `/api/workflow/app-templates` | 创建应用模板 |
| GET | `/api/workflow/app-templates` | 列表应用模板 |
| GET | `/api/workflow/app-templates/{template_id}` | 获取应用模板详情 |
| PUT | `/api/workflow/app-templates/{template_id}` | 更新应用模板 |
| DELETE | `/api/workflow/app-templates/{template_id}` | 删除应用模板 |

---

## Create App Template

**POST** `/api/workflow/app-templates`

创建应用模板。

**Authentication:** Required

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | 模板名称 (1-128字符) |
| description | string | No | 模板描述 |
| scope | string | No | 模板范围: `global`(全局) 或 `project`(项目)，默认: `project` |
| project_id | string | Conditional | 项目ID (scope为project时必填) |
| containers | array[ContainerConfig] | Yes | 容器配置列表 (至少一个容器) |
| service_ports | array[ServicePort] | No | K8s Service端口配置 |
| service_name | string | No | K8s Service名称 (不指定则自动生成) |
| create_service | boolean | No | 是否创建K8s Service默认: true |
| service_type | string | No | Service类型: `ClusterIP`(默认), `LoadBalancer`, `NodePort` |
| replicas | integer | No | 副本数默认: 1最小: 1 |

**ContainerConfig:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | 容器名称 (1-128字符) |
| image | string | Yes | 容器镜像地址 |
| command | array[string] | No | 启动命令 |
| args | array[string] | No | 命令参数 |
| env_vars | array[EnvVar] | No | 固定环境变量 |
| volume_mounts | array[VolumeMount] | No | 固定PVC挂载 |
| input_env_vars | array[EnvVarInput] | No | 输入环境变量依赖 |
| input_volume_mounts | array[VolumeMountInput] | No | 输入挂载依赖 |
| privileged | boolean | No | 特权模式默认: false |
| image_pull_policy | string | No | `Always`, `IfNotPresent`(默认), `Never` |
| resources | object | No | 资源要求 |
| liveness_probe | object | No | 存活探针配置 |
| readiness_probe | object | No | 就绪探针配置 |

**EnvVar:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | 环境变量名 |
| value | string | Yes | 环境变量值 |

**EnvVarInput:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | 环境变量名 (在当前容器设置) |
| default_value | string | No | 默认值 (当上游不可用时) |

**VolumeMount:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| pvc_name | string | Yes | PVC名称 |
| mount_path | string | Yes | 容器内挂载路径 |
| sub_path | string | No | PVC子目录挂载 |
| read_only | boolean | No | 只读挂载默认: false |

**VolumeMountInput:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| mount_path | string | Yes | 容器内需要挂载的路径 |
| sub_path | string | No | PVC子目录挂载 |
| read_only | boolean | No | 只读挂载默认: true |

**ServicePort:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | 端口名称 |
| port | integer | Yes | Service端口 (1-65535) |
| target_port | integer | Yes | 容器目标端口 (1-65535) |
| protocol | string | No | 协议默认: TCP |

**ResourceRequirements:**

| Field | Type | Description |
|-------|------|-------------|
| requests | object | 最小资源请求 `{cpu: "100m", memory: "128Mi"}` |
| limits | object | 资源限制 `{cpu: "500m", memory: "512Mi"}` |

**HealthCheckConfig:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | Yes | 健康检查类型: `http`, `tcp`, `exec` |
| port | integer | Conditional | 健康检查端口 (http/tcp类型必填) |
| path | string | Conditional | HTTP健康检查路径 (http类型必填) |
| command | array[string] | Conditional | Exec命令 (exec类型必填) |
| initial_delay_seconds | integer | No | 初始延迟秒数默认: 10 |
| period_seconds | integer | No | 检查周期秒数默认: 10 |
| timeout_seconds | integer | No | 超时秒数默认: 5 |
| failure_threshold | integer | No | 失败阈值默认: 3 |
| success_threshold | integer | No | 成功阈值默认: 1 |

**Request Example:**

```json
{
  "name": "my-app-template",
  "description": "My application template",
  "scope": "project",
  "project_id": "proj-001",
  "containers": [
    {
      "name": "web-container",
      "image": "nginx:latest",
      "command": ["/bin/sh"],
      "args": ["-c", "nginx -g 'daemon off;'"],
      "env_vars": [
        {"name": "ENV", "value": "production"}
      ],
      "volume_mounts": [
        {"pvc_name": "data-pvc", "mount_path": "/data", "read_only": false}
      ],
      "image_pull_policy": "IfNotPresent",
      "resources": {
        "requests": {"cpu": "100m", "memory": "128Mi"},
        "limit": {"cpu": "500m", "memory": "512Mi"}
      },
      "liveness_probe": {
        "type": "http",
        "path": "/healthz",
        "port": 8080,
        "initial_delay_seconds": 30,
        "period_seconds": 10
      },
      "readiness_probe": {
        "type": "http",
        "path": "/ready",
        "port": 8080,
        "initial_delay_seconds": 5,
        "period_seconds": 5
      }
    }
  ],
  "service_ports": [
    {"name": "http", "port": 80, "target_port": 8080}
  ],
  "replicas": 2,
  "create_service": true,
  "service_type": "ClusterIP"
}
```

**Response:** `201 Created`

**AppTemplateResponse:**

```json
{
  "id": "wf-tmpl-my-app-template-abc123",
  "name": "my-app-template",
  "description": "My application template",
  "scope": "project",
  "project_id": "proj-001",
  "containers": [...],
  "service_ports": [...],
  "replicas": 2,
  "service_name": "svc-my-app",
  "create_service": true,
  "service_type": "ClusterIP",
  "created_by": "user-001",
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
| 403 | 无权限 |
| 409 | 资源冲突 |

---

## List App Template

**GET** `/api/workflow/app-templates`

列表应用模板。

**Authentication:** Required

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| scope | string | 按范围过滤: `global`/`project` |
| project_id | string | 按项目ID过滤 |

**Response:** `200 OK`

**AppTemplateListResponse:**

```json
{
  "total": 1,
  "items": [
    {
      "id": "wf-tmpl-my-app-template-abc123",
      "name": "my-app-template",
      ...
    }
  ]
}
```

---

## Get App Template

**GET** `/api/workflow/app-templates/{template_id}`

获取应用模板详情。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| template_id | string | 模板ID |

**Response:** `200 OK`

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | 获取成功 |
| 401 | 未认证 |
| 403 | 无权限 |
| 404 | 模板不存在 |

---

## Update App Template

**PUT** `/api/workflow/app-templates/{template_id}`

更新应用模板。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| template_id | string | 模板ID |

**Request Body:**

所有创建时字段均为可选可只更新部分字段。

**Request Example:**

```json
{
  "name": "updated-name",
  "description": "Updated description",
  "replicas": 3
}
```

**Response:** `200 OK`

---

## Delete App Template

**DELETE** `/api/workflow/app-templates/{template_id}`

删除应用模板。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| template_id | string | 模板ID |

**Response:** `200 OK`

**SuccessResponse:**

```json
{
  "message": "App template wf-tmpl-my-app-template-abc123 deleted successfully"
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | 删除成功 |
| 401 | 未认证 |
| 403 | 无权限 |
| 404 | 模板不存在 |
