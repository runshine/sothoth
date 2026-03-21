# SecFlow 漏洞生命周期编排引擎 API 设计

## Base Path

`/api/vuln`

## 1. 健康检查

### `GET /api/vuln/health`

返回服务健康状态。

### `GET /api/vuln/ready`

返回服务就绪状态。

## 2. 服务注册

### `POST /api/vuln/services/register`

注册外部漏洞能力微服务。

请求示例：

```json
{
  "service_id": "secflow-vuln-poc-gen-01",
  "service_name": "POC Generator",
  "service_type": "poc_generator",
  "endpoint": "http://secflow-vuln-poc-gen",
  "healthcheck_url": "http://secflow-vuln-poc-gen/health",
  "callback_mode": "push",
  "auth_mode": "machine_token",
  "version": "1.0.0",
  "capabilities": [
    {
      "capability_code": "poc_generate_default",
      "action_type": "poc_generation",
      "priority": 100,
      "timeout_seconds": 600,
      "concurrency_limit": 5
    }
  ]
}
```

### `POST /api/vuln/services/heartbeat/{service_id}`

上报心跳。

### `DELETE /api/vuln/services/unregister/{service_id}`

注销服务。

### `GET /api/vuln/services`

查询已注册服务列表。

## 3. Case

### `POST /api/vuln/cases`

创建漏洞 Case。

### `GET /api/vuln/cases`

按项目和阶段过滤查询漏洞 Case。

### `GET /api/vuln/cases/{case_id}`

获取 Case 详情。

### `GET /api/vuln/cases/{case_id}/timeline`

获取时间线，包括事件、阶段流转、Action、Result。

## 4. 外部结果回调

### `POST /api/vuln/actions/{action_id}/callback`

外部能力服务回调执行结果。

请求示例：

```json
{
  "source_service_id": "secflow-vuln-poc-gen-01",
  "result_type": "poc",
  "status": "succeeded",
  "summary": "Generated 2 candidate POCs",
  "confidence": 80,
  "suggested_stage": "prove",
  "suggested_decision": "needs_more_evidence",
  "result_meta": {
    "proof_count": 2
  },
  "artifact_refs": [
    {
      "artifact_id": "art-001",
      "artifact_type": "poc_file"
    }
  ]
}
```

## 5. 后续预留接口

当前版本先预留，不实现复杂逻辑：

- `POST /api/vuln/cases/{case_id}/stage-transitions`
- `POST /api/vuln/cases/{case_id}/decisions`
- `POST /api/vuln/cases/{case_id}/actions/trigger`
- `POST /api/vuln/cases/{case_id}/artifacts/init`
- `POST /api/vuln/cases/{case_id}/artifacts/complete`
