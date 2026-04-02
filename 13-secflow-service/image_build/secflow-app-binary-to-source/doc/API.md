# secflow-app-binary-to-source API

Base Path: `/api/app/binary-to-source`

## 1. 健康检查

### GET `/health`

响应：
```json
{
  "status": "ok",
  "service": "secflow-app-binary-to-source-manager"
}
```

### GET `/ready`

响应：
```json
{
  "status": "ready",
  "service": "secflow-app-binary-to-source-manager"
}
```

## 2. 创建任务

### POST `/projects/{project_id}/tasks`

请求头：
- `Authorization: Bearer <token>`

请求体：
```json
{
  "name": "batch-001",
  "description": "ELF source restore",
  "priority": 5,
  "tags": ["reverse", "elf"],
  "elf_tasks": [
    {
      "elf_path": "/data/binary-to-source/input/a.elf",
      "file_list": ["/data/binary-to-source/input/a.map"],
      "output_subdir": "a",
      "metadata": {"case": "demo"}
    }
  ]
}
```

响应：
```json
{
  "message": "任务创建成功",
  "task_id": "2b6b2ca32904d019"
}
```

## 3. 列表查询

### GET `/projects/{project_id}/tasks?status=running&offset=0&limit=20`

响应：
```json
{
  "total": 1,
  "items": [
    {
      "id": "2b6b2ca32904d019",
      "project_id": "abc123",
      "name": "batch-001",
      "status": "running",
      "total_items": 2,
      "pending_items": 0,
      "queued_items": 0,
      "running_items": 1,
      "success_items": 1,
      "partial_items": 0,
      "failed_items": 0,
      "cancelled_items": 0,
      "result_summary": {},
      "created_at": "2026-04-02T00:00:00",
      "updated_at": "2026-04-02T00:00:05",
      "started_at": "2026-04-02T00:00:01",
      "finished_at": null,
      "cancel_requested_at": null,
      "description": "ELF source restore",
      "priority": 5,
      "tags": ["reverse", "elf"],
      "created_by": "1",
      "error_summary": null
    }
  ]
}
```

## 4. 任务详情

### GET `/projects/{project_id}/tasks/{task_id}`

返回父任务 + 子任务列表（每个 ELF 的执行状态、失败原因、输出文件列表、重试次数等）。

## 5. 更新任务元信息

### PATCH `/projects/{project_id}/tasks/{task_id}`

请求体（可选字段）：
```json
{
  "name": "batch-001-updated",
  "description": "new description",
  "priority": 7,
  "tags": ["important"]
}
```

## 6. 删除任务

### DELETE `/projects/{project_id}/tasks/{task_id}`

仅终态任务支持删除：
- `completed`
- `failed`
- `cancelled`
- `partial_success`

## 7. 终止任务

### POST `/projects/{project_id}/tasks/{task_id}/terminate`

行为：
- 父任务转 `cancelling`
- `pending` 子任务直接标记 `cancelled`
- `queued/running` 子任务发送 Celery revoke，并在 worker 侧安全退出

## 8. 手动重试

### POST `/projects/{project_id}/tasks/{task_id}/retry`

请求体：
```json
{
  "item_ids": ["subtask-id-1", "subtask-id-2"]
}
```

- `item_ids` 为空时，重试该任务下全部可重试失败子任务
- `worker_business_error` 默认不自动重试，但允许手动重试
- `transient_system_error` 可自动重试（按配置）

## 9. 状态与重试规则

- 自动重试仅适用于 `transient_system_error`
- `worker_business_error` 自动重试关闭
- 子任务运行超时会转 `transient_system_error`

## 10. 错误格式

```json
{
  "code": "VALIDATION_ERROR",
  "message": "elf_tasks 不能为空",
  "details": null
}
```
