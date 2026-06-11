# Turing M2M 机机接口文档

> **Base URL**: `/api/v1`  
> **协议**: HTTP/HTTPS  
> **Content-Type**: `application/json`  
> **字符编码**: UTF-8

---

## 概述

M2M（Machine-to-Machine）接口供上游系统以编程方式提交应用安全扫描任务，并管理任务的生命周期。每个任务对应一次完整的 APK/HAP 安全审计流程，包含反编译、探测（detection）、挖掘（mining）、校验（validation）四个阶段。

---

## 目录

- [数据模型](#数据模型)
  - [枚举值](#枚举值)
  - [公共结构体](#公共结构体)
- [接口列表](#接口列表)
  - [1. 创建扫描任务](#1-创建扫描任务)
  - [2. 查询任务列表](#2-查询任务列表)
  - [3. 查询任务状态](#3-查询任务状态)
  - [4. 删除任务](#4-删除任务)
  - [5. 暂停任务](#5-暂停任务)
  - [6. 恢复任务](#6-恢复任务)
- [错误处理](#错误处理)
- [状态机](#状态机)
- [调用示例](#调用示例)

---

## 数据模型

### 枚举值

#### ExternalTaskStatus — 任务状态

| 值 | 说明 |
|---|---|
| `pending` | 已创建，等待处理 |
| `decompiling` | 反编译进行中 |
| `running` | 扫描执行中 |
| `paused` | 已暂停 |
| `completed` | 已完成 |
| `failed` | 执行失败 |

#### TaskType — 文件类型

| 值 | 说明 |
|---|---|
| `APK` | Android 应用包 |
| `HAP` | HarmonyOS 应用包 |

### 公共结构体

#### PhaseProgress — 阶段进度

单阶段（detection / mining / validation）的任务计数。

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `total` | int | 否 | `0` | 该阶段总任务数 |
| `pending` | int | 否 | `0` | 等待执行 |
| `running` | int | 否 | `0` | 执行中 |
| `success` | int | 否 | `0` | 已成功 |
| `failed` | int | 否 | `0` | 已失败 |

#### TaskProgress — 三阶段进度汇总

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `phases` | `dict[str, PhaseProgress]` | 否 | `{}` | 键为阶段名（`detection` / `mining` / `validation`），值为该阶段计数 |

#### TokenUsage — Token 消耗统计

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `input` | int | 否 | `0` | 输入 Token 数 |
| `cache_read` | int | 否 | `0` | 缓存命中 Token 数 |
| `output` | int | 否 | `0` | 输出 Token 数 |
| `cost` | float | 否 | `0.0` | 总费用（美元） |

#### ExternalTaskSummary — 任务摘要

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `tool_task_id` | str | 是 | 系统生成的工具任务 ID |
| `external_project_id` | str | 是 | 上游项目 ID |
| `external_task_id` | str | 是 | 上游任务 ID |
| `task_type` | str | 是 | 文件类型（`APK` / `HAP`） |
| `status` | str | 是 | 当前状态 |
| `created_at` | str \| null | 否 | 创建时间（ISO 8601） |

---

## 接口列表

---

### 1. 创建扫描任务

提交一个应用安全扫描任务。系统将自动执行反编译、探测、挖掘、校验全流程。

```
POST /api/v1/tasks
```

#### 请求体

| 字段 | 类型 | 必填 | 约束 | 说明 |
|---|---|---|---|---|
| `project_id` | str | ✅ | 1–128 字符 | 上游项目 ID |
| `task_id` | str | ✅ | 1–128 字符 | 上游任务 ID |
| `file_path` | str | ✅ | ≥ 1 字符 | 服务器上 APK/HAP 文件的绝对路径 |
| `task_type` | TaskType | ✅ | `APK` 或 `HAP` | 文件类型 |

**请求示例：**

```json
{
  "project_id": "proj-20240610-001",
  "task_id": "task-20240610-001",
  "file_path": "/data/uploads/example.apk",
  "task_type": "APK"
}
```

#### 响应

**状态码**：`201 Created`

| 字段 | 类型 | 说明 |
|---|---|---|
| `tool_task_id` | str | 系统生成的工具任务 ID，格式 `TuringAppSecurity-{5位随机字母数字}-{13位毫秒时间戳}` |
| `project_id` | str | 内部项目 ID |
| `job_id` | str | 内部作业 ID |
| `status` | ExternalTaskStatus | 创建时固定为 `pending` |

**响应示例：**

```json
{
  "tool_task_id": "TuringAppSecurity-a3Fk9-1718012345678",
  "project_id": "proj-abc123",
  "job_id": "job-def456",
  "status": "pending"
}
```

#### 前置校验

| 校验项 | 失败状态码 | 说明 |
|---|---|---|
| 文件路径存在 | `422` | `file_path` 必须指向服务器上实际存在的文件 |
| 任务唯一性 | `409` | 同一 `(project_id, task_id)` 组合不可重复提交 |

#### 副作用

1. 创建内部项目和作业
2. 启动反编译进程
3. 在 `turing_external_task` 表中写入映射记录

---

### 2. 查询任务列表

分页查询已提交的外部扫描任务。

```
GET /api/v1/tasks
```

#### 查询参数

| 参数 | 类型 | 必填 | 默认值 | 约束 | 说明 |
|---|---|---|---|---|---|
| `project_id` | str | 否 | — | — | 按上游 project_id 过滤 |
| `offset` | int | 否 | `0` | ≥ 0 | 分页偏移量 |
| `limit` | int | 否 | `50` | 1–200 | 每页数量 |

**请求示例：**

```
GET /api/v1/tasks?project_id=proj-20240610-001&offset=0&limit=20
```

#### 响应

**状态码**：`200 OK`

| 字段 | 类型 | 说明 |
|---|---|---|
| `items` | `ExternalTaskSummary[]` | 任务摘要列表 |
| `total` | int | 符合条件的总记录数 |

**响应示例：**

```json
{
  "items": [
    {
      "tool_task_id": "TuringAppSecurity-a3Fk9-1718012345678",
      "external_project_id": "proj-20240610-001",
      "external_task_id": "task-20240610-001",
      "task_type": "APK",
      "status": "running",
      "created_at": "2024-06-10T08:30:00Z"
    }
  ],
  "total": 1
}
```

---

### 3. 查询任务状态

查询单个任务的详细状态，包含三阶段进度和 Token 消耗。

```
GET /api/v1/tasks/{tool_task_id}
```

#### 路径参数

| 参数 | 类型 | 说明 |
|---|---|---|
| `tool_task_id` | str | 创建任务时返回的工具任务 ID |

#### 响应

**状态码**：`200 OK`

| 字段 | 类型 | 说明 |
|---|---|---|
| `tool_task_id` | str | 工具任务 ID |
| `status` | ExternalTaskStatus | 当前任务状态 |
| `progress` | TaskProgress | 三阶段进度详情 |
| `token_usage` | TokenUsage | Token 消耗统计 |
| `created_at` | float \| null | 创建时间（Unix 时间戳，秒） |
| `started_at` | float \| null | 开始执行时间（Unix 时间戳，秒） |
| `completed_at` | float \| null | 完成时间（Unix 时间戳，秒） |
| `error` | str \| null | 失败时的错误信息 |

**响应示例：**

```json
{
  "tool_task_id": "TuringAppSecurity-a3Fk9-1718012345678",
  "status": "running",
  "progress": {
    "phases": {
      "detection": { "total": 10, "pending": 2, "running": 3, "success": 4, "failed": 1 },
      "mining": { "total": 5, "pending": 3, "running": 1, "success": 1, "failed": 0 },
      "validation": { "total": 0, "pending": 0, "running": 0, "success": 0, "failed": 0 }
    }
  },
  "token_usage": {
    "input": 125000,
    "cache_read": 80000,
    "output": 15000,
    "cost": 0.42
  },
  "created_at": 1718012345.678,
  "started_at": 1718012350.123,
  "completed_at": null,
  "error": null
}
```

#### 错误响应

| 状态码 | 说明 |
|---|---|
| `404` | `tool_task_id` 不存在 |

---

### 4. 删除任务

删除任务并清理所有关联资源。操作不可逆。

```
DELETE /api/v1/tasks/{tool_task_id}
```

#### 路径参数

| 参数 | 类型 | 说明 |
|---|---|---|
| `tool_task_id` | str | 工具任务 ID |

#### 响应

**状态码**：`200 OK`

| 字段 | 类型 | 说明 |
|---|---|---|
| `tool_task_id` | str | 工具任务 ID |
| `status` | str | 固定为 `"deleted"` |
| `message` | str | `"任务已删除，资源已清理"` |

**响应示例：**

```json
{
  "tool_task_id": "TuringAppSecurity-a3Fk9-1718012345678",
  "status": "deleted",
  "message": "任务已删除，资源已清理"
}
```

#### 清理顺序（容错）

以下步骤按序执行，即使某步失败也会继续后续步骤：

1. 取消反编译任务（标记 `CANCELLED`、移出 Redis 队列、杀死 jadx/hap 子进程）
2. 清理作业资源（取消 OpenCode 会话、释放并发配额）
3. 级联删除项目（覆盖 jobs / tasks / detections / findings）
4. 从 Redis 队列中移除任务 ID
5. 删除工作空间目录
6. 删除 `turing_external_task` 映射记录

---

### 5. 暂停任务

暂停正在执行或等待中的扫描任务。

```
POST /api/v1/tasks/{tool_task_id}/pause
```

#### 路径参数

| 参数 | 类型 | 说明 |
|---|---|---|
| `tool_task_id` | str | 工具任务 ID |

#### 响应

**状态码**：`200 OK`

| 字段 | 类型 | 说明 |
|---|---|---|
| `tool_task_id` | str | 工具任务 ID |
| `status` | str | 固定为 `"paused"` |
| `message` | str | `"任务已暂停"` |

**响应示例：**

```json
{
  "tool_task_id": "TuringAppSecurity-a3Fk9-1718012345678",
  "status": "paused",
  "message": "任务已暂停"
}
```

#### 前置校验

| 校验项 | 失败状态码 | 说明 |
|---|---|---|
| 作业存在 | `409` | 任务必须已开始（job 已创建） |
| 作业状态 | `409` | 作业必须处于 `running` 或 `pending` 状态 |

---

### 6. 恢复任务

从暂停点恢复任务执行。系统会根据当前反编译进度自动选择恢复策略。

```
POST /api/v1/tasks/{tool_task_id}/resume
```

#### 路径参数

| 参数 | 类型 | 说明 |
|---|---|---|
| `tool_task_id` | str | 工具任务 ID |

#### 响应

**状态码**：`200 OK`

| 字段 | 类型 | 说明 |
|---|---|---|
| `tool_task_id` | str | 工具任务 ID |
| `status` | str | `"running"` 或 `"decompiling"` |
| `message` | str | 操作说明 |

**场景 A — 反编译已完成：**

```json
{
  "tool_task_id": "TuringAppSecurity-a3Fk9-1718012345678",
  "status": "running",
  "message": "任务已恢复"
}
```

**场景 B — 反编译仍在进行中：**

```json
{
  "tool_task_id": "TuringAppSecurity-a3Fk9-1718012345678",
  "status": "decompiling",
  "message": "反编译仍在进行中，已排队等待反编译完成后自动恢复扫描"
}
```

#### 前置校验

| 校验项 | 失败状态码 | 说明 |
|---|---|---|
| 反编译未失败 | `409` | 项目状态不能为 `decompile_failed` |
| 作业存在 | `409` | job 必须已创建 |
| 作业已暂停 | `409` | 作业状态必须为 `paused` |
| 工作空间可用 | `422` | 工作空间路径必须存在 |

---

## 错误处理

所有错误均返回统一 JSON 格式：

```json
{
  "error": "错误描述信息"
}
```

### 错误码一览

| HTTP 状态码 | 错误场景 |
|---|---|
| `404` | `tool_task_id` 不存在，或关联的项目/作业已被删除 |
| `409` | 重复提交（相同 `project_id` + `task_id`）、状态不满足操作前置条件 |
| `422` | 文件路径不存在、不支持的文件类型、缺少工作空间 |
| `500` | 服务端内部异常 |

---

## 状态机

```
                    ┌──────────┐
                    │ pending  │ ← 创建任务
                    └────┬─────┘
                         │ 开始反编译
                         ▼
                  ┌──────────────┐
            ┌────▶│ decompiling  │◀───┐
            │     └──────┬───────┘    │
            │            │ 反编译完成  │ resume(反编译未完成)
            │            ▼            │
            │     ┌──────────────┐    │
            │  ┌─▶│   running    │────┤ pause
            │  │  └──────┬───────┘    │
            │  │         │            │
            │  │  resume │  pause     ▼
            │  │         ▼     ┌───────────┐
            │  │         ┌────▶│  paused   │
            │  │         │     └───────────┘
            │  │         │
            │  │         ▼
            │  │   ┌───────────┐
            │  └──▶│ completed │
            │      └───────────┘
            │
            │      ┌───────────┐
            └─────▶│  failed   │
                   └───────────┘
                        ▲
                        │ delete
                ┌───────┴────────┐
                │  任何状态均可删除  │
                └────────────────┘
```

**关键规则：**
- `delete` 操作可从**任意状态**发起
- `pause` 仅允许从 `running` 或 `pending`（job 级别）发起
- `resume` 仅允许从 `paused` 发起
- `decompile_failed` 为终态，不可 resume

---

## 调用示例

### cURL

**创建任务：**

```bash
curl -X POST http://localhost:8080/api/v1/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "my-project",
    "task_id": "my-task-001",
    "file_path": "/data/uploads/app.apk",
    "task_type": "APK"
  }'
```

**查询状态：**

```bash
curl http://localhost:8080/api/v1/tasks/TuringAppSecurity-a3Fk9-1718012345678
```

**暂停任务：**

```bash
curl -X POST http://localhost:8080/api/v1/tasks/TuringAppSecurity-a3Fk9-1718012345678/pause
```

**恢复任务：**

```bash
curl -X POST http://localhost:8080/api/v1/tasks/TuringAppSecurity-a3Fk9-1718012345678/resume
```

**删除任务：**

```bash
curl -X DELETE http://localhost:8080/api/v1/tasks/TuringAppSecurity-a3Fk9-1718012345678
```

**查询任务列表：**

```bash
curl "http://localhost:8080/api/v1/tasks?project_id=my-project&offset=0&limit=20"
```

### Python (requests)

```python
import requests

BASE = "http://localhost:8080/api/v1"

# 创建任务
resp = requests.post(f"{BASE}/tasks", json={
    "project_id": "my-project",
    "task_id": "my-task-001",
    "file_path": "/data/uploads/app.apk",
    "task_type": "APK",
})
task = resp.json()
tool_task_id = task["tool_task_id"]

# 轮询状态
import time
while True:
    status = requests.get(f"{BASE}/tasks/{tool_task_id}").json()
    print(f"状态: {status['status']}, 进度: {status['progress']}")
    if status["status"] in ("completed", "failed"):
        break
    time.sleep(30)

# 删除任务
requests.delete(f"{BASE}/tasks/{tool_task_id}")
```
