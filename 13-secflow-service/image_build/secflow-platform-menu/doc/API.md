# SecFlow Menu Service API 文档

## 概述

SecFlow Menu Service 是一个动态菜单注册管理微服务，提供服务的注册、管理和动态菜单查询功能。

- **服务名称**: secflow-menu
- **API 前缀**: `/api/menu`
- **默认端口**: 5000

---

## API 汇总

| 序号 | 方法 | 接口路径 | 说明 |
|------|------|----------|------|
| 1 | GET | `/api/menu/health` | 健康检查 |
| 2 | GET | `/api/menu/menu` | 获取动态菜单 |
| 3 | GET | `/api/menu/services` | 获取所有服务信息 |
| 4 | GET | `/api/menu/services/health` | 获取所有服务聚合健康状态 |
| 5 | GET | `/api/menu/services/health/summary` | 获取前端菜单健康汇总 |
| 6 | POST | `/api/menu/services/health/check/{service_id}` | 手动触发单服务健康检查 |
| 7 | POST | `/api/menu/register` | 注册/更新服务 |
| 8 | DELETE | `/api/menu/unregister/{service_id}` | 注销服务 |
| 9 | POST | `/api/menu/heartbeat/{service_id}` | 心跳检测 |
| 10 | GET | `/api/menu/maturity/list` | 获取成熟度列表 |

---

## 服务成熟度

服务成熟度分为三类：

| 成熟度 | 说明 |
|--------|------|
| `已上线` | 正式环境可用的服务 |
| `开发中` | 开发测试中的服务 |
| `规划中` | 规划中尚未开发的服务 |

---

## API 接口

### 1. 健康检查

**GET** `/api/menu/health`

检查服务是否正常运行。

**响应示例**:
```json
{
    "status": "ok",
    "service": "secflow-menu"
}
```

---

### 2. 获取动态菜单

**GET** `/api/menu/menu`

获取所有已注册的动态菜单项。

**响应示例**:
```json
{
    "code": 0,
    "message": "success",
    "data": [
        {
            "id": "home",
            "name": "首页",
            "path": "/home",
            "parentId": null,
            "icon": "home",
            "order": 0,
            "maturity": "已上线",
            "description": "系统首页"
        },
        {
            "id": "user-manage",
            "name": "用户管理",
            "path": "/user",
            "parentId": null,
            "icon": "user",
            "order": 1,
            "maturity": "开发中",
            "description": "用户管理模块"
        }
    ]
}
```

---

### 3. 获取所有服务信息

**GET** `/api/menu/services`

获取所有已注册服务的详细信息。

**响应示例**:
```json
{
    "code": 0,
    "message": "success",
    "data": [
        {
            "service_id": "secflow-user",
            "service_name": "用户服务",
            "host": "192.168.1.100",
            "port": 8080,
            "register_time": 1699999999.123,
            "last_heartbeat": 1700000000.456,
            "maturity": "已上线",
            "menu_item": {
                "id": "user-manage",
                "name": "用户管理",
                "path": "/user",
                "parent_id": null,
                "icon": "user",
                "order": 1,
                "maturity": "已上线",
                "service_name": "用户服务",
                "description": "用户管理模块"
            }
        }
    ]
}
```

---

### 4. 注册服务

### 4. 获取所有服务聚合健康状态

**GET** `/api/menu/services/health`

返回所有已注册服务的聚合健康状态明细。

**响应示例**:
```json
{
  "code": 0,
  "message": "success",
  "data": [
    {
      "service_id": "secflow-platform-vuln",
      "service_name": "漏洞生命周期引擎",
      "api_prefix": "/api/vuln",
      "menu_item_id": "vuln-root",
      "menu_path": "/vuln-overview",
      "health_url": "http://secflow.sothothv2.com/api/vuln/health",
      "health": {
        "status": "healthy",
        "last_check": 1700000000.123,
        "last_ok": 1700000000.123,
        "http_status": 200,
        "latency_ms": 12,
        "error": null,
        "consecutive_failures": 0,
        "heartbeat_age_seconds": 5.2
      }
    }
  ]
}
```

---

### 5. 获取前端菜单健康汇总

**GET** `/api/menu/services/health/summary`

返回适合前端菜单图标染色的轻量健康汇总。

**响应示例**:
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "generated_at": 1700000000.123,
    "totals": {
      "healthy": 5,
      "unhealthy": 1,
      "degraded": 0,
      "unknown": 2,
      "stale": 0
    },
    "services": {
      "secflow-platform-vuln": {
        "service_id": "secflow-platform-vuln",
        "service_name": "漏洞生命周期引擎",
        "api_prefix": "/api/vuln",
        "menu_item_id": "vuln-root",
        "menu_path": "/vuln-overview",
        "health": "healthy",
        "latency_ms": 12,
        "last_check_at": 1700000000.123,
        "error": null
      }
    }
  }
}
```

---

### 6. 手动触发单服务健康检查

**POST** `/api/menu/services/health/check/{service_id}`

立即执行一次指定服务的主动健康检查。

---

### 7. 注册服务

**POST** `/api/menu/register`

注册或更新服务。

**请求头**:
```
Content-Type: application/json
```

**请求体**:
```json
{
    "service_id": "secflow-user",
    "service_name": "用户服务",
    "host": "192.168.1.100",
    "port": 8080,
    "api_prefix": "/api/auth",
    "maturity": "已上线",
    "health_check": {
        "path": "/api/auth/health",
        "interval_seconds": 30,
        "timeout_seconds": 2
    },
    "menu_item": {
        "id": "user-manage",
        "name": "用户管理",
        "path": "/user",
        "parent_id": null,
        "icon": "user",
        "order": 1,
        "description": "用户管理模块"
    }
}
```

**参数说明**:

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| service_id | string | 是 | 服务唯一标识 |
| service_name | string | 是 | 服务名称 |
| host | string | 是 | 服务主机地址 |
| port | int | 是 | 服务端口 |
| api_prefix | string | 否 | 服务 API 前缀，用于自动推导健康检查地址 |
| maturity | string | 否 | 成熟度，默认"开发中" |
| health_check | object | 否 | 主动健康检查配置 |
| menu_item | object | 否 | 菜单配置 |

**health_check 参数说明**:

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| path | string | 否 | 健康检查路径，默认 `${api_prefix}/health` |
| url | string | 否 | 显式健康检查 URL，优先级最高 |
| method | string | 否 | 探测方法，默认 `GET` |
| interval_seconds | number | 否 | menu 端主动探测周期 |
| timeout_seconds | number | 否 | 单次探测超时时间 |

**menu_item 参数说明**:

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| id | string | 是 | 菜单项ID |
| name | string | 是 | 菜单名称 |
| path | string | 否 | 菜单路径，默认 /{service_name} |
| parent_id | string | 否 | 父菜单ID，支持多级菜单 |
| icon | string | 否 | 菜单图标 |
| order | int | 否 | 排序序号 |
| description | string | 否 | 描述 |

**响应示例**:
```json
{
    "code": 0,
    "message": "success",
    "status": "registered"
}
```

---

### 8. 注销服务

**DELETE** `/api/menu/unregister/{service_id}`

注销服务。

**URL参数**:
- `service_id`: 服务ID

**响应示例**:
```json
{
    "code": 0,
    "message": "success"
}
```

---

### 9. 心跳检测

**POST** `/api/menu/heartbeat/{service_id}`

向服务发送心跳。

**URL参数**:
- `service_id`: 服务ID

**响应示例**:
```json
{
    "code": 0,
    "message": "success"
}
```

---

### 7. 获取成熟度列表

**GET** `/api/menu/maturity/list`

获取所有可选的成熟度列表。

**响应示例**:
```json
{
    "code": 0,
    "message": "success",
    "data": ["已上线", "开发中", "规划中"]
}
```

---

## 其他微服务注册示例

### Python 示例

```python
import requests
import time

SERVICE_URL = "http://secflow-menu-service:5000/api/menu"

def register_service():
    payload = {
        "service_id": "my-service",
        "service_name": "我的服务",
        "host": "my-service",
        "port": 8080,
        "maturity": "已上线",
        "menu_item": {
            "id": "my-menu",
            "name": "我的菜单",
            "path": "/my-menu",
            "parent_id": None,
            "icon": "setting",
            "order": 10,
            "description": "我的服务菜单"
        }
    }
    response = requests.post(f"{SERVICE_URL}/register", json=payload)
    return response.json()

def heartbeat():
    response = requests.post(f"{SERVICE_URL}/heartbeat/my-service")
    return response.json()

# 注册服务
register_service()

# 定时心跳（建议每10秒一次）
while True:
    heartbeat()
    time.sleep(10)
```

### 注册格式完整示例

```json
{
    "service_id": "secflow-user",
    "service_name": "用户服务",
    "host": "user-service",
    "port": 8080,
    "maturity": "已上线",
    "menu_item": {
        "id": "user-manage",
        "name": "用户管理",
        "path": "/user-manage",
        "parent_id": null,
        "icon": "user",
        "order": 1,
        "description": "用户管理模块"
    }
}
```

---

## 配置说明

### config.yaml 配置项

```yaml
# 服务配置
host: "0.0.0.0"      # 服务监听地址
port: 5000           # 服务监听端口
debug: false         # 调试模式

# 心跳超时配置（秒）
heartbeat_timeout: 30.0

# 清理过期服务间隔（秒）
cleanup_interval: 10

# 日志配置
log_level: "INFO"
```

---

## 部署

### 本地运行

```bash
# 安装依赖
pip install -r requirements.txt

# 启动服务
python app.py --config config.yaml
```

### Docker 部署

```bash
# 构建镜像
docker build -t secflow-menu .

# 运行容器
docker run -d \
    --name secflow-menu \
    -p 5000:5000 \
    -v $(pwd)/config.yaml:/app/config.yaml \
    secflow-menu
```

### Kubernetes 部署

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: secflow-menu-config
data:
  config.yaml: |
    host: "0.0.0.0"
    port: 5000
    heartbeat_timeout: 30.0
    cleanup_interval: 10

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secflow-menu
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secflow-menu
  template:
    metadata:
      labels:
        app: secflow-menu
    spec:
      containers:
      - name: secflow-menu
        image: secflow-menu:latest
        ports:
        - containerPort: 5000
        volumeMounts:
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
      volumes:
      - name: config
        configMap:
          name: secflow-menu-config
```

---

## 多级菜单支持

系统支持多级菜单，通过 `parent_id` 字段实现。

### 示例：二级菜单

```json
{
    "service_id": "secflow-user",
    "menu_item": {
        "id": "system",
        "name": "系统管理",
        "order": 1,
        "parent_id": null
    }
}
```

```json
{
    "service_id": "secflow-user",
    "menu_item": {
        "id": "user-manage",
        "name": "用户管理",
        "order": 1,
        "parent_id": "system"
    }
}
```

---

## 注意事项

1. 服务启动时会从 `config.yaml` 读取配置
2. 其他微服务需要定期发送心跳（建议每10秒一次）
3. 超过心跳超时时间（默认30秒）的服务会被自动清理
4. 成熟度用于前端展示，建议与实际服务状态保持一致
