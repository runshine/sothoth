
# API Documentation

本文档按接口面划分 GaiaSec LLM Gateway 当前对外接口。

- 推理调用面：模型调用、模型列表，面向业务调用方。
- 凭证签发面：通过 task key 生成 work key，面向任务运行方。
- 配置管理面：算力池、后端单元、模型别名、路由绑定、LLM Key 管理，面向管理后台。
- 日志观测面：请求日志、回放、统计，面向运维和审计。
- 健康检查面：存活检查，面向部署平台。

## 通用约定

## 调度中心接入约定

当前 `chirmera-platform-schedule` 与 AI Gateway 的职责边界固定如下：

- 创建业务任务时，不要求用户手动填写任何 task key、secret 或 capacity pool。
- 调度中心只负责登记业务任务与输入绑定，任务创建阶段不访问 AI Gateway。
- 用户点击“分发”后，调度中心使用服务端管理凭证调用 `POST /api/aigw/llm-keys` 创建一个新的 **root task key**。
- 这个 root task key 会直接传给下游微服务，用作本次任务的父级运行凭证。
- 下游如果需要更细粒度的 worker / sub-task 凭证，由实际编排方直接基于 root task key 调用 `POST /api/aigw/work-keys`。
- 调度中心本期不创建 work key，也不保存下游派生出的 work key。

推荐调度流程：

1. `POST /api/chirmera-platform-schedule/projects/{project_id}/user-tasks`
2. `POST /api/chirmera-platform-schedule/projects/{project_id}/user-tasks/{task_id}/dispatch`
3. 调度中心在 dispatch 内部调用 `POST /api/aigw/llm-keys`
4. 调度中心把返回的 root task key secret 直接用于 downstream create / upload complete / start
5. `binary-security` 这类编排方在创建下游子任务前，可直接调用 `POST /api/aigw/work-keys`
6. 更下游执行方如需继续细分凭证，可再自行调用 `POST /api/aigw/work-keys`

### Base URL

```text
http://{gateway-host}:{port}
```

### 认证

推理调用面和凭证签发面使用 LLM Key：

```http
Authorization: Bearer tsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Authorization: Bearer wsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

- `tsk_`：task key，任务级授权父 key。
- `wsk_`：work key，任务执行子 key。

配置管理面和日志观测面当前代码中未实现独立管理鉴权，部署层应自行加网关鉴权、内网访问控制或反向代理鉴权。

### 错误响应

多数接口错误响应为 `text/plain`：

```text
error message
```

常见状态码：

| 状态码 | 说明 |
| --- | --- |
| `400` | 请求体 JSON 错误、必填字段缺失或参数非法。 |
| `401` | Bearer Token 缺失、无效、已禁用或已过期。 |
| `403` | Key 无权限访问目标模型、任务身份不匹配，或接口要求 task key 但传入 work key。 |
| `404` | 资源不存在。 |
| `405` | HTTP Method 不允许。 |
| `429` | Key 或后端并发限制触发。 |
| `500` | 数据库、上游调用或服务端内部错误。 |

## 推理调用面

### POST /chat/completions

OpenAI Chat Completions 兼容接口。

等价路径：

- `POST /chat/completions`
- `POST /v1/chat/completions`

请求头：

```http
Authorization: Bearer tsk_xxx 或 Bearer wsk_xxx
Content-Type: application/json
```

请求体透传 OpenAI Chat Completions 格式，至少需要 `model`：

```json
{
  "model": "gpt-4o-mini",
  "messages": [
    {
      "role": "user",
      "content": "hello"
    }
  ],
  "stream": false
}
```

说明：

- `model` 对应 `model_aliases.alias_name`。
- 非流式响应透传上游 JSON。
- `stream=true` 时响应为 SSE 流。
- task key 和 work key 都可以调用；work key 的模型和算力池权限继承父 task key。
- 调用会写入 `/api/aigw/request-logs`。

### POST /v1/responses

OpenAI Responses 兼容接口。

等价路径：

- `POST /v1/responses`
- `POST /responses`

请求头：

```http
Authorization: Bearer tsk_xxx 或 Bearer wsk_xxx
Content-Type: application/json
```

请求体透传 OpenAI Responses 格式，至少需要 `model`：

```json
{
  "model": "gpt-4o-mini",
  "input": "hello",
  "stream": false
}
```

说明：

- 只会路由到后端单元中 `supports_responses=true` 的 backend unit。
- 非流式响应透传上游 JSON。
- `stream=true` 时响应为 SSE 流。

### POST /v1/messages

Anthropic Messages 兼容接口。

请求头：

```http
Authorization: Bearer tsk_xxx 或 Bearer wsk_xxx
Content-Type: application/json
```

请求体至少需要 `model`：

```json
{
  "model": "claude-compatible-alias",
  "messages": [
    {
      "role": "user",
      "content": "hello"
    }
  ],
  "max_tokens": 1024,
  "stream": false
}
```

说明：

- 只会路由到后端单元中 `supports_messages=true` 的 backend unit。
- 响应格式透传上游。

### GET /v1/models

查询当前 key 可访问的模型列表。

请求头：

```http
Authorization: Bearer tsk_xxx 或 Bearer wsk_xxx
```

成功响应：

```json
{
  "object": "list",
  "data": [
    {
      "id": "gpt-4o-mini",
      "object": "model",
      "created": 1780886400,
      "owned_by": "system"
    }
  ]
}
```

说明：

- 仅返回 enabled 的 model alias。
- 返回结果会按 key 的算力池 scope 过滤。

## 凭证签发面

### POST /api/aigw/work-keys

通过 task key 生成 work key。调用方使用已有 task key 作为 Bearer Token，网关根据凭证解析父级 task key 并写入 `parent_key_id`。调用方不需要传 `parent_key_id`。

请求头：

```http
Authorization: Bearer tsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Content-Type: application/json
```

请求体：

```json
{
  "key_name": "worker-1",
  "sub_task_id": "sub-a",
  "max_concurrency": 0,
  "enabled": true,
  "description": "work key for task-a/sub-a"
}
```

字段说明：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `key_name` | string | 否 | Key 名称；不传时默认使用 `work-{sub_task_id}`。 |
| `sub_task_id` | string | 是 | Work key 的子任务 ID。 |
| `max_concurrency` | number | 否 | 并发限制。`0` 表示不单独限制；运行时 work key 并发归入父 task key。 |
| `enabled` | boolean | 否 | 是否启用；不传时默认为 `true`。 |
| `expires_at` | string | 否 | 过期时间，建议使用 RFC3339 格式。 |
| `description` | string | 否 | 描述。 |

成功响应：`201 Created`

```json
{
  "key": {
    "id": 12,
    "key_name": "worker-1",
    "key_type": "work",
    "parent_key_id": 1,
    "key_prefix": "wsk_xxxxxxxx",
    "max_concurrency": 0,
    "task_id": "task-a",
    "sub_task_id": "sub-a",
    "enabled": true,
    "description": "work key for task-a/sub-a",
    "capacity_pool_ids": [],
    "created_at": "2026-06-08T00:00:00Z",
    "updated_at": "2026-06-08T00:00:00Z"
  },
  "secret": "wsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

注意：

- `secret` 只在创建成功时返回一次。
- Bearer Token 必须是 task key；使用 work key 调用会返回 `403`。
- work key 不维护独立 scope，模型和算力池权限继承父 task key。

## 配置管理面

配置管理接口统一使用 `/api/aigw` 前缀。

### Backend Unit

Backend unit 表示真实上游模型服务，通常由 `api_base_url + model_name + api_key_ciphertext` 标识。

资源字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | number | 后端单元 ID。 |
| `capacity_pool_id` | number | 所属算力池 ID。 |
| `api_base_url` | string | 上游 API Base URL。 |
| `model_name` | string | 上游真实模型名。 |
| `api_key_ciphertext` | string | 上游 API Key。 |
| `api_key_fingerprint` | string | 上游 API Key 指纹。 |
| `total_max_concurrency` | number | 后端总并发限制，`0` 表示不限制。 |
| `priority_default` | number | 默认优先级。 |
| `supports_chat_completions` | boolean | 是否支持 Chat Completions。 |
| `supports_responses` | boolean | 是否支持 Responses。 |
| `supports_messages` | boolean | 是否支持 Messages。 |
| `enabled` | boolean | 是否启用。 |
| `description` | string | 描述。 |
| `created_at` | string | 创建时间。 |
| `updated_at` | string | 更新时间。 |

接口：

| Method | Path | 说明 |
| --- | --- | --- |
| `GET` | `/api/aigw/backend-units` | 列表。 |
| `POST` | `/api/aigw/backend-units` | 创建。 |
| `GET` | `/api/aigw/backend-units/{id}` | 详情。 |
| `PUT` | `/api/aigw/backend-units/{id}` | 更新。 |
| `DELETE` | `/api/aigw/backend-units/{id}` | 删除，并删除相关 model alias binding。 |
| `POST` | `/api/aigw/backend-units/{id}/test` | 测试上游连接。 |

创建/更新请求示例：

```json
{
  "capacity_pool_id": 1,
  "api_base_url": "https://api.openai.com/v1",
  "model_name": "gpt-4o-mini",
  "api_key_ciphertext": "sk-xxx",
  "api_key_fingerprint": "fp_xxx",
  "total_max_concurrency": 20,
  "priority_default": 0,
  "supports_chat_completions": true,
  "supports_responses": true,
  "supports_messages": false,
  "enabled": true,
  "description": "openai gpt-4o-mini"
}
```

连接测试响应：

```json
{
  "success": true,
  "data": {
    "success": true,
    "message": "连接测试成功",
    "input": {},
    "output": {}
  }
}
```

### Capacity Pool

Capacity pool 表示算力池，用于限制 key 可访问的后端集合。

资源字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | number | 算力池 ID。 |
| `pool_name` | string | 算力池名称。 |
| `enabled` | boolean | 是否启用。 |
| `description` | string | 描述。 |
| `created_at` | string | 创建时间。 |
| `updated_at` | string | 更新时间。 |

接口：

| Method | Path | 说明 |
| --- | --- | --- |
| `GET` | `/api/aigw/capacity-pools` | 列表。 |
| `POST` | `/api/aigw/capacity-pools` | 创建。 |
| `GET` | `/api/aigw/capacity-pools/{id}` | 详情。 |
| `PUT` | `/api/aigw/capacity-pools/{id}` | 更新。 |
| `DELETE` | `/api/aigw/capacity-pools/{id}` | 删除，并清理 backend unit 关联和 key scope。 |

创建/更新请求示例：

```json
{
  "pool_name": "default-pool",
  "enabled": true,
  "description": "default capacity pool"
}
```

### Model Alias

Model alias 是调用方面向 `/chat/completions`、`/v1/responses` 等接口传入的公开模型名。

资源字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | number | 模型别名 ID。 |
| `alias_name` | string | 公开模型名。 |
| `max_tokens_default` | number | 默认最大输出 token。 |
| `temperature_default` | number | 默认 temperature。 |
| `enabled` | boolean | 是否启用。 |
| `description` | string | 描述。 |
| `created_at` | string | 创建时间。 |
| `updated_at` | string | 更新时间。 |

接口：

| Method | Path | 说明 |
| --- | --- | --- |
| `GET` | `/api/aigw/model-aliases` | 列表。 |
| `POST` | `/api/aigw/model-aliases` | 创建。 |
| `GET` | `/api/aigw/model-aliases/{id}` | 详情。 |
| `PUT` | `/api/aigw/model-aliases/{id}` | 更新。 |
| `DELETE` | `/api/aigw/model-aliases/{id}` | 删除。 |

创建/更新请求示例：

```json
{
  "alias_name": "gpt-4o-mini",
  "max_tokens_default": 8192,
  "temperature_default": 0.7,
  "enabled": true,
  "description": "public model alias"
}
```

### Model Alias Binding

Model alias binding 定义公开模型名到后端单元的路由关系。

资源字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | number | 绑定 ID。 |
| `model_alias_id` | number | 模型别名 ID。 |
| `backend_unit_id` | number | 后端单元 ID。 |
| `priority` | number | 路由优先级，越小越优先。 |
| `weight` | number | 权重。 |
| `enabled` | boolean | 是否启用。 |
| `created_at` | string | 创建时间。 |
| `updated_at` | string | 更新时间。 |

接口：

| Method | Path | 说明 |
| --- | --- | --- |
| `GET` | `/api/aigw/model-alias-bindings` | 列表，按 `priority ASC, id DESC` 排序。 |
| `POST` | `/api/aigw/model-alias-bindings` | 创建。 |
| `GET` | `/api/aigw/model-alias-bindings/{id}` | 详情。 |
| `PUT` | `/api/aigw/model-alias-bindings/{id}` | 更新。 |
| `DELETE` | `/api/aigw/model-alias-bindings/{id}` | 删除。 |

创建/更新请求示例：

```json
{
  "model_alias_id": 1,
  "backend_unit_id": 10,
  "priority": 0,
  "weight": 100,
  "enabled": true
}
```

### LLM Key

LLM Key 管理接口用于后台创建和管理 task key / work key。业务调用方生成 work key 时优先使用凭证签发面的 `POST /api/aigw/work-keys`。

资源字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | number | Key ID。 |
| `key_name` | string | Key 名称。 |
| `key_type` | string | `task` 或 `work`。 |
| `parent_key_id` | number | work key 的父 task key ID。 |
| `key_prefix` | string | Key 前缀。 |
| `max_concurrency` | number | 并发限制。 |
| `task_id` | string | 任务 ID。 |
| `sub_task_id` | string | 子任务 ID。 |
| `enabled` | boolean | 是否启用。 |
| `expires_at` | string | 过期时间。 |
| `description` | string | 描述。 |
| `capacity_pool_ids` | array | task key 可访问的算力池 ID 列表。 |
| `created_at` | string | 创建时间。 |
| `updated_at` | string | 更新时间。 |

接口：

| Method | Path | 说明 |
| --- | --- | --- |
| `GET` | `/api/aigw/llm-keys` | 列表。 |
| `POST` | `/api/aigw/llm-keys` | 创建 task key 或管理侧创建 work key。 |
| `GET` | `/api/aigw/llm-keys/{id}` | 详情。 |
| `PUT` | `/api/aigw/llm-keys/{id}` | 更新。 |
| `DELETE` | `/api/aigw/llm-keys/{id}` | 删除。 |

创建 task key 请求示例：

```json
{
  "key_name": "task-key-a",
  "key_type": "task",
  "task_id": "task-a",
  "max_concurrency": 10,
  "enabled": true,
  "capacity_pool_ids": [1, 2],
  "description": "task key for task-a"
}
```

创建 task key 成功响应：

```json
{
  "key": {
    "id": 1,
    "key_name": "task-key-a",
    "key_type": "task",
    "key_prefix": "tsk_xxxxxxxx",
    "max_concurrency": 10,
    "task_id": "task-a",
    "sub_task_id": "",
    "enabled": true,
    "description": "task key for task-a",
    "capacity_pool_ids": [1, 2],
    "created_at": "2026-06-08T00:00:00Z",
    "updated_at": "2026-06-08T00:00:00Z"
  },
  "secret": "tsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

管理侧创建 work key 请求示例：

```json
{
  "key_name": "work-key-a",
  "key_type": "work",
  "parent_key_id": 1,
  "task_id": "task-a",
  "sub_task_id": "sub-a",
  "enabled": true,
  "description": "admin-created work key"
}
```

约束：

- 创建 task key 时必须传 `task_id` 和至少一个 `capacity_pool_ids`。
- 创建 task key 时不能传 `parent_key_id`。
- 创建 work key 时必须传 `parent_key_id` 和 `sub_task_id`。
- 创建 work key 时 `task_id` 必须与父 task key 一致。
- 创建 work key 时不能传 `capacity_pool_ids`。
- 更新时 `key_type`、`parent_key_id`、`task_id`、`sub_task_id` 不可变。
- work key 更新时不能写 `capacity_pool_ids`。
- `secret` 只在创建成功时返回一次。

## 日志观测面

### GET /api/aigw/request-logs

分页查询请求日志。

查询参数：

| 参数 | 说明 |
| --- | --- |
| `model` | 按公开模型名过滤。 |
| `llm_key_id` | 按实际调用 key ID 过滤。 |
| `task_key_id` | 按父 task key ID 过滤。 |
| `task_id` | 按任务 ID 过滤。 |
| `sub_task_id` | 按子任务 ID 过滤。 |
| `model_alias_id` | 按模型别名 ID 过滤。 |
| `capacity_pool_id` | 按算力池 ID 过滤。 |
| `backend_unit_id` | 按后端单元 ID 过滤。 |
| `backend_model` | 按后端真实模型名过滤。 |
| `start_date` | 起始时间，RFC3339。 |
| `end_date` | 结束时间，RFC3339。 |
| `page` | 页码，默认 `1`。 |
| `page_size` / `size` | 每页数量，默认 `20`，最大 `100`。 |

成功响应：

```json
{
  "total": 1,
  "logs": [
    {
      "id": 100,
      "created_at": "2026-06-08T00:00:00Z",
      "endpoint": "chat.completions",
      "is_stream": false,
      "status_code": 200,
      "model_name": "gpt-4o-mini",
      "llm_key_id": 12,
      "llm_key_prefix": "wsk_xxxxxxxx",
      "task_key_id": 1,
      "task_key_prefix": "tsk_xxxxxxxx",
      "task_id": "task-a",
      "sub_task_id": "sub-a",
      "model_alias_id": 1,
      "capacity_pool_id": 1,
      "backend_unit_id": 10,
      "backend_model_name": "gpt-4o-mini",
      "response_time": 1234,
      "first_token_latency": 200,
      "avg_token_latency": 30,
      "request_preview": "hello",
      "prompt_tokens": 10,
      "completion_tokens": 20,
      "total_tokens": 30,
      "gateway_cache_hit": false
    }
  ]
}
```

### GET /api/aigw/request-logs/{id}

查询单条请求日志详情。

成功响应为 `models.RequestLog` 完整结构，包含请求体、响应体、流式响应字节统计、token、成本和缓存字段。

### DELETE /api/aigw/request-logs

清空请求日志。

成功响应：

```json
{
  "message": "All logs cleared successfully"
}
```

### POST /api/aigw/request-logs/{id}/replay

基于历史请求回放。

请求体：

```json
{
  "override": {
    "temperature": 0,
    "stream": false
  }
}
```

说明：

- 读取指定日志的原始 request。
- `override` 中的字段会覆盖原始请求。
- 当前回放走 Chat Completions 后端路由。

成功响应：

```json
{
  "original_request": "{\"model\":\"gpt-4o-mini\",\"messages\":[]}",
  "modified_request": "{\"model\":\"gpt-4o-mini\",\"messages\":[],\"temperature\":0}",
  "original_response": "{}",
  "new_response": "{}",
  "model_name": "gpt-4o-mini",
  "actual_model_name": "gpt-4o-mini",
  "response_time": 1234
}
```

### GET /api/aigw/stats

查询最近 1 小时聚合统计。

成功响应：

```json
{
  "total_requests": 100,
  "active_models": 3,
  "model_alias_bindings": 5,
  "avg_response_time": 1200,
  "avg_first_token_latency": 200,
  "avg_token_latency": 30,
  "active_requests": 2,
  "waiting_requests": 0
}
```

### GET /api/aigw/stats/providers

按后端单元维度查询最近 1 小时统计。

成功响应：

```json
[
  {
    "model_name": "gpt-4o-mini",
    "request_count": 100,
    "avg_response_time": 1200,
    "avg_first_token_latency": 200,
    "avg_token_latency": 30,
    "active_requests": 2,
    "waiting_requests": 0,
    "success_rate": 0.99,
    "backend_unit_id": 10,
    "backend_model_name": "gpt-4o-mini",
    "backend_api_base_url": "https://api.openai.com/v1",
    "adaptive_routing_score": 0.95
  }
]
```

### GET /api/aigw/stats/models

按公开模型别名维度查询最近 1 小时统计。

成功响应：

```json
[
  {
    "model_name": "gpt-4o-mini",
    "request_count": 100,
    "avg_response_time": 1200,
    "avg_first_token_latency": 200,
    "avg_token_latency": 30,
    "model_alias_id": 1
  }
]
```

## 健康检查面

### GET /actuator/health

健康检查。

成功响应：

```text
ok
```

### GET /health

轻量健康检查。

成功响应：

```text
ok
```

### GET /healthz

Kubernetes 风格健康检查。

成功响应：

```text
ok
```
