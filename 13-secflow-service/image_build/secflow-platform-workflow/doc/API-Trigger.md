# 触发器 API

通过HTTP触发工作流执行。

## Trigger Workflow via HTTP

**POST** `/api/workflow/trigger/{instance_id}`

通过HTTP请求触发持久化工作流实例执行。

**Authentication:** Not Required (内部使用)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| instance_id | string | 实例ID |

**Description:**

- 仅对persistent模式、HTTP触发器类型有效
- 需要trigger_enabled=true和is_active=true
- 工作流异步执行

**触发器工作流程:**

1. 创建persistent模式工作流实例设置 `trigger_type: "http"`, `trigger_enabled: true`
2. 调用激活端点 `POST /{instance_id}/activate` 使工作流处于激活状态
3. 外部系统通过HTTP POST请求触发工作流执行
4. 工作流执行完成后保持节点状态等待下一次触发

**Response:** `200 OK`

**SuccessResponse:**

```json
{
  "message": "Workflow wf-inst-my-workflow-jkl012 triggered successfully"
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | 触发成功 |
| 400 | 触发器未启用/非激活状态/非HTTP类型/已运行中 |
| 404 | 实例不存在 |
| 500 | 触发失败 |
