# Agent Service Manager API Manual

## Overview

Agent Service Manager 是一个基于 Flask 的微服务，提供 Agent 管理、任务管理、模板管理和代理转发功能。

## Base URL

```
http://{host}:{port}/api/agent
```

## API Endpoints Summary

| Category | Endpoint | Method | Description |
|----------|----------|--------|-------------|
| Health | `/health` | GET | 服务健康检查 |
| Health | `/system/connections` | GET | 获取连接状态 |
| Project | `/projects` | GET | 列出所有项目 |
| Agent | `/agents` | GET | 列出指定项目下的所有 Agent |
| Agent | `/agents/refresh` | POST | 刷新 Agent 列表 |
| Agent | `/agents/cleanup` | POST | 清理掉线 Agent |
| Agent | `/agents/stats` | GET | 获取指定项目的 Agent 统计信息 |
| Agent | `/agents/<agent_key>/status` | PUT | 更新指定项目下 Agent 状态 |
| Agent | `/agents/<agent_key>` | GET | 获取指定项目下的单个 Agent 信息 |
| Task | `/task` | GET | 列出指定项目下的所有任务 |
| Task | `/task/<task_id>` | GET | 获取指定项目下的任务详情 |
| Task | `/task/<task_id>/logs` | GET | 获取指定项目下的任务日志 |
| Task | `/task/<task_id>` | DELETE | 删除指定项目下的任务 |
| Task | `/task/deploy` | POST | 创建部署任务（需指定 project_id）|
| Task | `/task/undeploy` | POST | 创建卸载任务（需指定 project_id）|
| Proxy | `/proxy/<agent_key>/<path:action_path>` | GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD | 代理请求到 Agent |
| Proxy | `/proxy_simple/<agent_key>/<path:action_path>` | GET | 简单代理（仅 GET） |
| Proxy | `/agent/<agent_key>/<path:action_path>` | GET, POST, PUT, DELETE, PATCH | 简化版代理 |
| Proxy | `/agent/<agent_key>/system/info` | GET | 获取 Agent 系统信息 |
| Proxy | `/agent/<agent_key>/services` | GET | 获取 Agent 服务列表 |
| Proxy | `/agent/<agent_key>/health` | GET | 获取 Agent 健康状态 |
| Proxy | `/proxy/debug/<agent_key>` | GET | 调试 Agent 代理连接 |
| Proxy | `/proxy/info` | GET | 获取代理 API 信息 |
| Proxy | `/proxy/test/<agent_key>` | GET | 测试代理连接 |
| Proxy | `/proxy/examples` | GET | 获取代理使用示例 |
| Template | `/templates` | GET | 列出所有模板（全局共享，无需 project_id）|
| Template | `/templates` | POST | 上传模板（全局共享，无需 project_id）|
| Template | `/templates/<name>` | GET | 获取模板详情（全局共享）|
| Template | `/templates/<name>/yaml` | GET | 获取模板 YAML 内容 |
| Template | `/templates/<name>/yaml` | PUT | 更新模板 YAML 内容 |
| Template | `/templates/<name>/download` | GET | 下载模板 |
| Template | `/templates/<name>/file` | GET | 获取模板原始文件 |
| Template | `/templates/<name>/content` | GET | 获取模板内容（JSON 格式）|
| Template | `/templates/<name>/info` | GET | 获取模板信息 |
| Template | `/templates/<name>` | DELETE | 删除模板 |
| Template | `/templates/download/batch` | POST | 批量下载模板 |
| Template | `/templates/<name>/files` | GET | 列出模板文件 |
| Template | `/templates/<name>/files/content` | GET | 获取模板文件内容 |
| Template | `/templates/<name>/files/content` | PUT | 更新模板文件内容 |
| Template | `/templates/<name>/files/download` | GET | 下载模板文件 |
| Template | `/templates/<name>/files/upload` | POST | 上传文件到模板 |
| Template | `/templates/<name>/files` | DELETE | 删除模板文件 |
| Template | `/templates/<name>/directories` | DELETE | 删除模板目录 |

---

## API Details

### Health Endpoints

#### GET /health

服务健康检查。

**Response:**
```json
{
  "status": "healthy|unhealthy",
  "timestamp": "2024-01-01T00:00:00",
  "pod_id": "string",
  "database_type": "sqlite|mysql",
  "component": {
    "database": "connected|disconnected",
    "redis": "connected|disconnected",
    "nacos": "connected|disconnected"
  },
  "supported_formats": [".zip", ".tar.gz", ".tar", ".tgz"]
}
```

---

#### GET /system/connections

获取系统连接状态。

**Response:**
```json
{
  "timestamp": "2024-01-01T00:00:00",
  "connection": {
    "database": {
      "status": "connected|disconnected",
      "message": "string",
      "type": "sqlite|mysql"
    },
    "nacos": {
      "status": "connected|disconnected",
      "message": "string"
    },
    "redis": {
      "status": "connected|disabled",
      "message": "string",
      "enabled": true
    }
  },
  "supported_formats": [".zip", ".tar.gz", ".tar", ".tgz"]
}
```

---

### Project Endpoints

#### GET /projects

列出所有项目。

**Response:**
```json
{
  "projects": [
    {
      "id": "string",
      "agent_count": 0,
      "online_agents": 0,
      "services_count": 0,
      "last_refresh": "2024-01-01T00:00:00",
      "agents": []
    }
  ],
  "total": 1
}
```

---

### Agent Endpoints

#### GET /agents

列出指定项目下的所有 Agent。

**Query Parameters:**
- `page` (int): 页码，默认 1
- `per_page` (int): 每页数量，默认 20
- `project_id` (string, **必需**): 项目 ID 过滤

**Response:**
```json
{
  "agents": [
    {
      "key": "string",
      "ip_address": "string",
      "hostname": "string",
      "project_id": "string",
      "status": "online|offline|error|unknown",
      "last_seen": "2024-01-01T00:00:00"
    }
  ],
  "page": 1,
  "per_page": 20,
  "total": 100,
  "project_id": "string"
}
```

**Error Response:**
```json
{
  "error": "project_id parameter is required"
}
```

---

#### POST /agents/refresh

刷新 Agent 列表。

**Response:**
```json
{
  "message": "Agent列表刷新完成"
}
```

---

#### POST /agents/cleanup

清理指定项目下掉线的 Agent。

**Request Body:**
```json
{
  "project_id": "project-1",
  "dry_run": false,
  "force": false
}
```

**Request Body Parameters:**
- `project_id` (string, **必需**): 项目 ID
- `dry_run` (bool): 模拟运行，只返回统计信息，默认 false
- `force` (bool): 是否强制清理（不检查时间），默认 false

**Response:**
```json
{
  "message": "清理完成",
  "success": true,
  "cleanup_info": {
    "cleaned_count": 5,
    "remaining_count": 10
  },
  "offline_count_before": 15,
  "total_count_before": 25,
  "project_id": "project-1",
  "timestamp": "2024-01-01T00:00:00"
}
```

**Error Response:**
```json
{
  "error": "project_id is required"
}
```

---

#### GET /agents/stats

获取指定项目的 Agent 统计信息。

**Query Parameters:**
- `project_id` (string, **必需**): 项目 ID

**Response:**
```json
{
  "timestamp": "2024-01-01T00:00:00",
  "project_id": "project-1",
  "summary": {
    "total_agents": 100,
    "offline_agents": 5,
    "status_distribution": {
      "online": 80,
      "offline": 10,
      "error": 5,
      "unknown": 5
    }
  },
  "status_details": [],
  "cleanup_info": {
    "can_cleanup": true,
    "offline_count": 5,
    "suggested_action": "POST /api/agent/agents/cleanup 清理掉线agent"
  }
}
```

**Error Response:**
```json
{
  "error": "project_id parameter is required"
}
```

---

#### PUT /agents/<agent_key>/status

手动更新指定项目下 Agent 状态。

**Path Parameters:**
- `agent_key` (string): Agent 唯一标识

**Request Body:**
```json
{
  "status": "online|offline|error|timeout|unknown",
  "project_id": "string"
}
```

**Response:**
```json
{
  "message": "Agent abc123 状态已更新为 online",
  "agent_key": "abc123",
  "project_id": "project-1",
  "new_status": "online",
  "updated_at": "2024-01-01T00:00:00",
  "updated_by": "system"
}
```

**Error Response:**
```json
{
  "error": "project_id is required"
}
```
或
```json
{
  "error": "Agent abc123 does not belong to project project-1"
}
```

---

#### GET /agents/<agent_key>

获取指定项目下的单个 Agent 信息。

**Path Parameters:**
- `agent_key` (string): Agent 唯一标识

**Query Parameters:**
- `project_id` (string, **必需**): 项目 ID

**Response:**
```json
{
  "key": "abc123",
  "ip_address": "192.168.1.100",
  "hostname": "agent-host-1",
  "project_id": "project-1",
  "full_name": "Agent 1",
  "status": "online",
  "pod_id": "pod-abc123",
  "last_seen": "2024-01-01T00:00:00",
  "system_info": {},
  "services": [],
  "requested_project_id": "project-1"
}
```

**Error Response:**
```json
{
  "error": "project_id parameter is required"
}
```
或
```json
{
  "error": "Agent abc123 does not belong to project project-1"
}
```

---

### Task Endpoints

#### GET /task

列出指定项目下的所有任务。

**Query Parameters:**
- `page` (int): 页码，默认 1
- `per_page` (int): 每页数量，默认 20
- `type` (string): 任务类型过滤
- `status` (string): 状态过滤
- `project_id` (string, **必需**): 项目 ID 过滤
- `agent_key` (string): Agent 唯一标识

**Response:**
```json
{
  "tasks": [
    {
      "task_id": "task-1",
      "type": "deploy|undeploy",
      "service_name": "myservice",
      "agent_key": "abc123",
      "template_name": "nginx",
      "status": "pending|running|completed|failed",
      "created_at": "2024-01-01T00:00:00",
      "updated_at": "2024-01-01T00:00:00"
    }
  ],
  "page": 1,
  "per_page": 20,
  "total": 50,
  "project_id": "project-1"
}
```

**Error Response:**
```json
{
  "error": "project_id parameter is required"
}
```

---

#### GET /task/<task_id>

获取任务详情。

**Path Parameters:**
- `task_id` (string): 任务 ID

**Query Parameters:**
- `project_id` (string, **必需**): 项目 ID（用于验证任务归属）

**Response:**
```json
{
  "task_id": "task-1",
  "type": "deploy",
  "project_id": "project-1",
  "service_name": "myservice",
  "agent_key": "abc123",
  "template_name": "nginx",
  "status": "running",
  "extra_params": {},
  "result": {},
  "created_at": "2024-01-01T00:00:00",
  "updated_at": "2024-01-01T00:00:00"
}
```

**Error Response:**
```json
{
  "error": "project_id parameter is required"
}
```
或
```json
{
  "error": "Task task-1 does not belong to project project-1"
}
```

---

#### GET /task/<task_id>/logs

获取任务日志。

**Path Parameters:**
- `task_id` (string): 任务 ID

**Query Parameters:**
- `page` (int): 页码，默认 1
- `per_page` (int): 每页数量，默认 100
- `project_id` (string, **必需**): 项目 ID（用于验证任务归属）

**Response:**
```json
{
  "log": [
    {
      "id": 1,
      "task_id": "task-1",
      "level": "INFO",
      "message": "任务开始执行",
      "timestamp": "2024-01-01T00:00:00"
    }
  ],
  "task_id": "task-1",
  "project_id": "project-1",
  "page": 1,
  "per_page": 100,
  "total": 1000
}
```

**Error Response:**
```json
{
  "error": "project_id parameter is required"
}
```
或
```json
{
  "error": "Task task-1 does not belong to project project-1"
}
```

---

#### DELETE /task/<task_id>

删除任务。

**Path Parameters:**
- `task_id` (string): 任务 ID

**Query Parameters:**
- `project_id` (string, **必需**): 项目 ID（用于验证任务归属）

**Response:**
```json
{
  "message": "任务删除成功",
  "task_id": "task-1",
  "project_id": "project-1"
}
```

**Error Response:**
```json
{
  "error": "project_id parameter is required"
}
```
或
```json
{
  "error": "Task task-1 does not belong to project project-1"
}
```

---

#### POST /task/deploy

创建部署任务。

**Request Body:**
```json
{
  "service_name": "myservice",
  "agent_key": "abc123",
  "template_name": "nginx",
  "project_id": "project-1",
  "extra_params": {}
}
```

**Request Body Parameters:**
- `service_name` (string, **必需**): 服务名称
- `agent_key` (string, **必需**): Agent 唯一标识
- `template_name` (string, **必需**): 模板名称
- `project_id` (string, **必需**): 项目 ID
- `extra_params` (object): 额外参数（可选）

**Response:**
```json
{
  "task_id": "task-123",
  "message": "部署任务已创建",
  "project_id": "project-1"
}
```

**Error Response:**
```json
{
  "error": "project_id不能为空"
}
```
或
```json
{
  "error": "Agent abc123 不属于项目 project-1"
}
```

---

#### POST /task/undeploy

创建卸载任务。

**Request Body:**
```json
{
  "service_name": "myservice",
  "agent_key": "abc123",
  "project_id": "project-1"
}
```

**Request Body Parameters:**
- `service_name` (string, **必需**): 服务名称
- `agent_key` (string, **必需**): Agent 唯一标识
- `project_id` (string, **必需**): 项目 ID

**Response:**
```json
{
  "task_id": "task-124",
  "message": "卸载任务已创建",
  "project_id": "project-1"
}
```

**Error Response:**
```json
{
  "error": "project_id不能为空"
}
```
或
```json
{
  "error": "Agent abc123 不属于项目 project-1"
}
```

---

### Proxy Endpoints

#### ALL /proxy/<agent_key>/<path:action_path>

将请求代理到指定的 Agent。

**Path Parameters:**
- `agent_key` (string): Agent 唯一标识
- `action_path` (string): 目标路径

**Supported Methods:** GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD

**Query Parameters:**
- `stream` (bool): 是否流式传输
- `timeout` (int): 超时时间（秒）

**Example:**
```bash
curl -X GET http://server:18080/api/agent/proxy/abc123/api/system/info
curl -X POST http://server:18080/api/agent/proxy/abc123/api/services/nginx/start
```

---

#### GET /proxy_simple/<agent_key>/<path:action_path>

简单代理到 Agent（仅 GET 请求）。

**Path Parameters:**
- `agent_key` (string): Agent 唯一标识
- `action_path` (string): 目标路径

---

#### ALL /agent/<agent_key>/<path:action_path>

简化版代理路由（自动添加 /api 前缀）。

**Path Parameters:**
- `agent_key` (string): Agent 唯一标识
- `action_path` (string): 目标路径（不含 /api）

**Supported Methods:** GET, POST, PUT, DELETE, PATCH

**Example:**
```bash
# 等价于 /api/proxy/abc123/api/system/info
curl http://server:18080/api/agent/agent/abc123/system/info
```

---

#### GET /agent/<agent_key>/system/info

获取 Agent 系统信息（快捷方式）。

**Path Parameters:**
- `agent_key` (string): Agent 唯一标识

---

#### GET /agent/<agent_key>/services

获取 Agent 服务列表（快捷方式）。

**Path Parameters:**
- `agent_key` (string): Agent 唯一标识

---

#### GET /agent/<agent_key>/health

获取 Agent 健康状态（快捷方式）。

**Path Parameters:**
- `agent_key` (string): Agent 唯一标识

---

#### GET /proxy/debug/<agent_key>

调试 Agent 代理连接。

**Path Parameters:**
- `agent_key` (string): Agent 唯一标识

**Response:**
```json
{
  "agent": {
    "key": "abc123",
    "hostname": "agent-host-1",
    "ip_address": "192.168.1.100",
    "status": "online",
    "last_seen": "2024-01-01T00:00:00"
  },
  "test_results": [
    {
      "endpoint": "/api/health",
      "status_code": 200,
      "response_time": "10.50ms",
      "success": true
    },
    {
      "endpoint": "/api/system/info",
      "status_code": 200,
      "response_time": "15.20ms",
      "success": true
    }
  ],
  "summary": {
    "total_tests": 4,
    "successful_tests": 4,
    "success_rate": "100.0%",
    "agent_available": true
  }
}
```

---

#### GET /proxy/info

获取代理 API 信息。

**Response:**
```json
{
  "available_agents": [
    {
      "key": "abc123",
      "hostname": "agent-host-1",
      "ip_address": "192.168.1.100",
      "project_id": "project-1",
      "status": "online",
      "last_seen": "2024-01-01T00:00:00"
    }
  ],
  "supported_formats": [".zip", ".tar.gz", ".tar", ".tgz"]
}
```

---

#### GET /proxy/test/<agent_key>

测试代理连接。

**Path Parameters:**
- `agent_key` (string): Agent 唯一标识

**Response:**
```json
{
  "agent_key": "abc123",
  "connection_test": "success|failed",
  "status_code": 200,
  "response": {},
  "agent_info": {},
  "timestamp": "2024-01-01T00:00:00"
}
```

---

#### GET /proxy/examples

获取代理使用示例。

**Response:**
```json
{
  "description": "代理API允许通过Server访问Agent的所有API",
  "basic_usage": {
    "pattern": "/api/proxy/{agent_key}/{action_path}",
    "methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
    "note": "action_path可以是任意路径，包括多层路径"
  },
  "simple_usage": {
    "pattern": "/api/agent/{agent_key}/{action_path}",
    "methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
    "note": "自动添加/api前缀，action_path不需要包含/api"
  },
  "quick_access": {
    "/api/agent/{agent_key}/system/info": "GET - 获取Agent系统信息",
    "/api/agent/{agent_key}/services": "GET - 获取Agent服务列表",
    "/api/agent/{agent_key}/health": "GET - 检查Agent健康状态"
  },
  "examples": [],
  "tips": []
}
```

---

### Template Endpoints

#### GET /templates

列出所有模板。

**Query Parameters:**
- `page` (int): 页码，默认 1
- `per_page` (int): 每页数量，默认 20

**Response:**
```json
{
  "templates": [
    {
      "name": "nginx",
      "type": "archive",
      "description": "Nginx 模板",
      "file_size": 1024,
      "directory_size": 2048,
      "created_at": "2024-01-01T00:00:00",
      "updated_at": "2024-01-01T00:00:00"
    }
  ],
  "page": 1,
  "per_page": 20,
  "total": 10,
  "supported_formats": [".zip", ".tar.gz", ".tar", ".tgz"]
}
```

---

#### POST /templates

上传模板。

**Content-Type:** `multipart/form-data`

**Form Parameters:**
- `file` (file): 模板文件
- `name` (string): 模板名称
- `description` (string): 模板描述（可选）
- `type` (string): 模板类型（auto/yaml/archive，默认 auto）

**Response:**
```json
{
  "message": "模板上传成功",
  "template_name": "nginx",
  "template_type": "archive",
  "filename": "nginx.zip"
}
```

---

#### GET /templates/<name>

获取模板详情。

**Path Parameters:**
- `name` (string): 模板名称

**Response:**
```json
{
  "name": "nginx",
  "type": "archive",
  "description": "Nginx 模板",
  "file_info": {
    "file_path": "/path/to/nginx.zip",
    "size": 1024,
    "type": "archive"
  },
  "directory_files": [
    {
      "name": "docker-compose.yml",
      "path": "docker-compose.yml",
      "size": 500,
      "modified": "2024-01-01T00:00:00"
    }
  ]
}
```

---

#### GET /templates/<name>/yaml

获取模板 YAML 内容。

**Path Parameters:**
- `name` (string): 模板名称

**Response:**
```json
{
  "name": "nginx",
  "yaml_content": "version: \"3\"...",
  "status": "success"
}
```

---

#### PUT /templates/<name>/yaml

更新模板 YAML 内容。

**Path Parameters:**
- `name` (string): 模板名称

**Request Body:**
```json
{
  "yaml_content": "version: \"3\"..."
}
```

**Response:**
```json
{
  "message": "YAML内容更新成功",
  "template": {},
  "status": "success"
}
```

---

#### GET /templates/<name>/download

下载模板。

**Path Parameters:**
- `name` (string): 模板名称

**Query Parameters:**
- `format` (string): 导出格式（original/zip/tar.gz，默认 original）
- `as_zip` (bool): 是否下载为 ZIP 包
- `include_all` (bool): 是否包含所有文件，默认 true
- `disposition` (string): Content-Disposition 类型

**Response:** 文件下载

---

#### GET /templates/<name>/file

获取模板原始文件。

**Path Parameters:**
- `name` (string): 模板名称

**Response:** 文件内容

---

#### GET /templates/<name>/content

获取模板内容（JSON 格式）。

**Path Parameters:**
- `name` (string): 模板名称

**Response:**
```json
{
  "name": "nginx",
  "type": "archive",
  "content_type": "application/zip",
  "content_encoding": "base64",
  "content": "base64encoded...",
  "size": 1024,
  "file_size": 1024,
  "directory_size": 2048,
  "created_at": "2024-01-01T00:00:00",
  "updated_at": "2024-01-01T00:00:00"
}
```

---

#### GET /templates/<name>/info

获取模板详细信息。

**Path Parameters:**
- `name` (string): 模板名称

**Response:**
```json
{
  "name": "nginx",
  "type": "archive",
  "description": "Nginx 模板",
  "file_info": {},
  "directory_info": {
    "path": "/path/to/templates/nginx",
    "total_files": 5,
    "total_size": 5000,
    "files": []
  }
}
```

---

#### DELETE /templates/<name>

删除模板。

**Path Parameters:**
- `name` (string): 模板名称

**Response:**
```json
{
  "message": "模板删除成功"
}
```

---

#### POST /templates/download/batch

批量下载模板。

**Request Body:**
```json
{
  "templates": ["nginx", "mysql"],
  "format": "original",
  "include_all": true
}
```

**Response:** ZIP 文件下载

---

#### GET /templates/<name>/files

列出模板目录下的所有文件和目录。

**Path Parameters:**
- `name` (string): 模板名称

**Query Parameters:**
- `path` (string): 目录路径，默认空（根目录）

**Response:**
```json
{
  "template_name": "nginx",
  "path": "",
  "files": [
    {
      "name": "docker-compose.yml",
      "path": "docker-compose.yml",
      "type": "file",
      "size": 500
    }
  ],
  "status": "success"
}
```

---

#### GET /templates/<name>/files/content

获取模板目录下指定文件的内容。

**Path Parameters:**
- `name` (string): 模板名称

**Query Parameters:**
- `path` (string): 文件路径
- `encoding` (string): 编码，默认 utf-8
- `preview` (bool): 预览模式，默认 false
- `max_size` (int): 预览最大大小，默认 1MB

**Response:**
```json
{
  "template_name": "nginx",
  "file_info": {
    "name": "docker-compose.yml",
    "path": "docker-compose.yml",
    "size": 500,
    "is_text": true
  },
  "content_type": "text/yaml",
  "is_text": true,
  "content": "version: \"3\"...",
  "encoding": "utf-8",
  "status": "success"
}
```

---

#### PUT /templates/<name>/files/content

更新模板目录下指定文件的内容。

**Path Parameters:**
- `name` (string): 模板名称

**Request Body:**
```json
{
  "path": "docker-compose.yml",
  "content": "version: \"3\"...",
  "encoding": "utf-8",
  "content_encoding": ""
}
```

**Response:**
```json
{
  "message": "文件更新成功",
  "update_info": {},
  "file_info": {},
  "status": "success"
}
```

---

#### GET /templates/<name>/files/download

下载模板目录下的单个文件。

**Path Parameters:**
- `name` (string): 模板名称

**Query Parameters:**
- `path` (string): 文件路径

**Response:** 文件下载

---

#### POST /templates/<name>/files/upload

上传文件到模板目录。

**Path Parameters:**
- `name` (string): 模板名称

**Content-Type:** `multipart/form-data`

**Form Parameters:**
- `file` (file): 文件
- `path` (string): 目标路径（可选）
- `overwrite` (bool): 是否覆盖（可选）

**Response:**
```json
{
  "message": "文件上传成功",
  "update_info": {},
  "filename": "custom.conf",
  "path": "custom.conf",
  "size": 100,
  "status": "success"
}
```

---

#### DELETE /templates/<name>/files

删除模板目录下的指定文件。

**Path Parameters:**
- `name` (string): 模板名称

**Request Body:**
```json
{
  "path": "custom.conf"
}
```

**Response:**
```json
{
  "message": "文件删除成功",
  "delete_info": {},
  "status": "success"
}
```

---

#### DELETE /templates/<name>/directories

删除模板目录下的指定目录。

**Path Parameters:**
- `name` (string): 模板名称

**Request Body:**
```json
{
  "path": "subdir",
  "force": false
}
```

**Response:**
```json
{
  "message": "目录删除成功",
  "delete_info": {},
  "status": "success"
}
```

---

## Error Response Format

所有错误响应遵循以下格式：

```json
{
  "error": "错误描述",
  "message": "详细错误信息",
  "timestamp": "2024-01-01T00:00:00"
}
```

**HTTP Status Codes:**
- `400`: 请求参数错误
- `404`: 资源不存在
- `409`: 资源冲突
- `500`: 服务器内部错误

---

## Supported Formats

模板管理支持以下压缩格式：
- `.zip`
- `.tar.gz`
- `.tar`
- `.tgz`
