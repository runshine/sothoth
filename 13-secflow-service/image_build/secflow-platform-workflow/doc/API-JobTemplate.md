# 任务模板 API

管理一次性Job模板。

## API 列表

| 方法 | 端点 | 描述 |
|------|------|------|
| POST | `/api/workflow/job-templates` | 创建任务模板 |
| GET | `/api/workflow/job-templates` | 列表任务模板 |
| GET | `/api/workflow/job-templates/{template_id}` | 获取任务模板详情 |
| PUT | `/api/workflow/job-templates/{template_id}` | 更新任务模板 |
| DELETE | `/api/workflow/job-templates/{template_id}` | 删除任务模板 |

---

## Create Job Template

**POST** `/api/workflow/job-templates`

创建Job模板 (支持多容器)。

**Authentication:** Required

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | 模板名称 (1-128字符) |
| description | string | No | 模板描述 |
| scope | string | No | 模板范围: `global` 或 `project`，默认: `project` |
| project_id | string | Conditional | 项目ID (scope为project时必填) |
| containers | array[ContainerConfig] | Yes | 容器配置列表 (至少一个) |
| ttl_seconds_after_finished | integer | No | 完成后TTL秒数默认: 3600 |
| backoff_limit | integer | No | 重试次数默认: 3 |

> 注意: 任务模板容器不支持健康检查 (liveness_probe, readiness_probe)。

**Request Example:**

```json
{
  "name": "my-job-template",
  "description": "My batch job",
  "scope": "project",
  "project_id": "proj-001",
  "containers": [
    {
      "name": "job-container",
      "image": "my-job:latest",
      "command": ["/bin/run.sh"],
      "env_vars": [
        {"name": "BATCH_SIZE", "value": "100"}
      ]
    }
  ],
  "ttl_seconds_after_finished": 1800,
  "backoff_limit": 5
}
```

**Response:** `201 Created`

**JobTemplateResponse:**

```json
{
  "id": "wf-tmpl-my-job-template-def456",
  "name": "my-job-template",
  "description": "My batch job",
  "scope": "project",
  "project_id": "proj-001",
  "containers": [...],
  "ttl_seconds_after_finished": 1800,
  "backoff_limit": 5,
  "created_by": "user-001",
  "created_at": "2026-02-25T10:00:00",
  "updated_at": "2026-02-25T10:00:00"
}
```

---

## List Job Template

**GET** `/api/workflow/job-templates`

列表任务模板。

**Authentication:** Required

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| scope | string | 按范围过滤: `global`/`project` |
| project_id | string | 按项目ID过滤 |

**Response:** `200 OK`

**JobTemplateListResponse:**

```json
{
  "total": 1,
  "items": [
    {
      "id": "wf-tmpl-my-job-template-def456",
      "name": "my-job-template",
      ...
    }
  ]
}
```

---

## Get Job Template

**GET** `/api/workflow/job-templates/{template_id}`

获取任务模板详情。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| template_id | string | 模板ID |

**Response:** `200 OK`

---

## Update Job Template

**PUT** `/api/workflow/job-templates/{template_id}`

更新任务模板。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| template_id | string | 模板ID |

**Request Body:**

所有创建时字段均为可选。

**Request Example:**

```json
{
  "ttl_seconds_after_finished": 3600
}
```

**Response:** `200 OK`

---

## Delete Job Template

**DELETE** `/api/workflow/job-templates/{template_id}`

删除任务模板。

**Authentication:** Required

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| template_id | string | 模板ID |

**Response:** `200 OK`

**SuccessResponse:**

```json
{
  "message": "Job template wf-tmpl-my-job-template-def456 deleted successfully"
}
```