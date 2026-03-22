# SecFlow 漏洞生命周期编排引擎 API 汇总

Base Path: `/api/vuln`

本文档只描述当前已经实现并可用的接口。

## 1. 健康检查

### `GET /api/vuln/health`

返回服务存活状态。

响应示例：

```json
{
  "status": "ok",
  "service": "secflow-platform-vuln"
}
```

### `GET /api/vuln/ready`

返回服务就绪状态。

## 2. 能力服务注册

### `POST /api/vuln/services/register`

注册外部能力微服务及其 capability。

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
  "meta": {},
  "capabilities": [
    {
      "capability_code": "poc_generate_default",
      "action_type": "poc_generation",
      "priority": 100,
      "timeout_seconds": 600,
      "concurrency_limit": 5,
      "input_schema_meta": {},
      "output_schema_meta": {
        "result_type": "poc"
      },
      "meta": {}
    }
  ]
}
```

### `POST /api/vuln/services/heartbeat/{service_id}`

刷新服务心跳。

### `DELETE /api/vuln/services/unregister/{service_id}`

注销能力服务。

### `GET /api/vuln/services`

获取已注册服务列表。

### `GET /api/vuln/services/{service_id}`

获取单个服务详情。

## 3. Case 管理

### `POST /api/vuln/cases`

创建新的漏洞 `Case`，并自动创建默认 `workflow_run`。

请求示例：

```json
{
  "project_id": "44f9029d00650a10",
  "title": "SNMP external high risk suspected issue",
  "summary": "Imported from external analysis module",
  "severity": "high",
  "confidence": 72,
  "source_meta": {
    "source_service": "secflow-snmp-analyzer",
    "source_event_id": "evt-001"
  },
  "target_meta": {
    "asset_type": "network_device",
    "asset_locator": "10.10.10.1:161"
  },
  "display_meta": {
    "preferred_render_type": "generic"
  },
  "created_by_type": "human",
  "created_by": "admin"
}
```

### `GET /api/vuln/cases`

查询 `Case` 列表。

支持查询参数：

- `project_id`
- `current_stage`

### `GET /api/vuln/cases/{case_id}`

获取 `Case` 详情。

返回内容包括：

- `case` 基础字段
- `workflow_run`
- `actions`
- `results`
- `manual_tasks`

### `GET /api/vuln/cases/{case_id}/timeline`

获取 `Case` 时间线。

时间线 item 类型包括：

- `event`
- `stage_history`
- `result`

## 4. 工作台与运营接口

### `GET /api/vuln/cases/ops/dashboard/overview`

项目级总览。

支持查询参数：

- `project_id`

返回聚合指标包括：

- `total_cases`
- `running_cases`
- `waiting_external`
- `manual_tasks_open`
- `registered_services`
- `active_services`
- `queued_actions`
- `stage_counts`
- `decision_counts`
- `action_status_counts`
- `result_type_counts`
- `recent_cases`

### `GET /api/vuln/cases/ops/manual-tasks`

项目级人工任务查询。

支持查询参数：

- `project_id`
- `status`

## 5. 人工任务

### `POST /api/vuln/cases/{case_id}/manual-tasks`

为指定 `Case` 创建人工任务。

请求示例：

```json
{
  "task_type": "manual_review",
  "title": "低置信度结果人工复核",
  "summary": "请确认当前结果是否可进入 decide 阶段",
  "assignee": "alice",
  "context": {
    "source": "automation"
  }
}
```

### `POST /api/vuln/cases/{case_id}/manual-tasks/{task_id}/status`

更新人工任务状态。

请求示例：

```json
{
  "status": "completed"
}
```

当前常用状态：

- `open`
- `in_progress`
- `completed`

## 6. 阶段与裁决

### `POST /api/vuln/cases/{case_id}/stage-transition`

人工推进阶段。

请求示例：

```json
{
  "to_stage": "decide",
  "reason": "operator_force_transition"
}
```

### `POST /api/vuln/cases/{case_id}/decisions`

提交人工裁决。

请求示例：

```json
{
  "decision_status": "confirmed",
  "summary": "人工确认成立，进入 track"
}
```

当前常用裁决值：

- `unknown`
- `suspected`
- `confirmed`
- `false_positive`
- `accepted_risk`
- `needs_more_evidence`

## 7. Action 派发与编排

### `POST /api/vuln/cases/{case_id}/actions/dispatch`

按路由规则手动派发 `Action`。

请求体：

```json
{
  "action_type": "poc_generation",
  "service_id": "secflow-vuln-poc-gen-01",
  "stage": "prove",
  "input_meta": {},
  "input_artifact_refs": []
}
```

### `GET /api/vuln/cases/{case_id}/recommended-actions`

返回当前阶段的推荐动作列表。

推荐信息包括：

- `service_id`
- `service_name`
- `service_type`
- `capability_code`
- `action_type`
- `priority`
- `recommended_stage`
- `already_active`

### `POST /api/vuln/cases/{case_id}/orchestrate/auto`

一键自动编排当前 `Case`，按推荐动作批量派发。

### `GET /api/vuln/actions/ops/queue`

项目级 `Action` 队列查询。

支持查询参数：

- `project_id`
- `execution_status`

### `POST /api/vuln/actions/mock-dispatch/{case_id}`

创建一条调试用 mock action。

## 8. Action 回调与控制

### `POST /api/vuln/actions/{action_id}/callback`

外部能力服务回调结果。

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
  "raw_payload": {
    "generator": "llm+preset",
    "version": "2026.03"
  },
  "artifact_refs": [
    {
      "artifact_id": "art-001",
      "artifact_type": "poc_file"
    }
  ]
}
```

平台会执行：

- 写入 `Result`
- 更新 `ActionExecution`
- 应用自动推进规则
- 必要时生成人工任务

### `POST /api/vuln/actions/{action_id}/control`

控制已派发 `Action`。

请求示例：

```json
{
  "operation": "retry"
}
```

当前支持：

- `retry`
- `cancel`

## 9. 认证与权限

当前接口统一依赖平台认证与项目访问校验：

- 认证通过 `auth` 服务校验 token
- 涉及项目数据时通过 `project` 服务做访问控制

## 10. 当前保留但尚未落地的方向

API 层已经为后续扩展留出空间，但当前未完整实现：

- Artifact 文件上传/下载接口
- 对象存储签名访问
- 更复杂的工作流模板管理
- 更细粒度的反馈与关系模型
