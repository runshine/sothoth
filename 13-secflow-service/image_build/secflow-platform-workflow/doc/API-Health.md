# 健康检查 API

服务健康状态检查。

## Health Check

**GET** `/api/workflow/health`

健康检查端点。

**Authentication:** Not Required

**Response:** `200 OK`

```json
{
  "status": "ok",
  "service": "secflow-workflow-service"
}
```

---

## Ready Check

**GET** `/api/workflow/ready`

就绪检查端点。

**Authentication:** Not Required

**Response:** `200 OK`

```json
{
  "status": "ready"
}
```