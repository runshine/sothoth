# SecFlow Menu Service

## 简介

SecFlow Menu Service 是一个动态菜单注册管理微服务，用于提供服务的注册管理和动态菜单查询功能。

## 功能特性

- **服务注册管理**：支持动态注册、注销服务
- **心跳检测**：自动检测服务存活状态
- **聚合健康检查**：由 menu 主动探测后端微服务健康状态
- **动态菜单**：根据注册信息动态生成菜单
- **成熟度分类**：支持已上线、开发中、规划中三种成熟度
- **多级菜单**：支持多级菜单结构
- **多副本共享状态**：通过 Redis 共享注册信息与健康缓存

## 项目结构

```
secflow_menu/
├── app.py              # 主应用文件
├── config.yaml         # 配置文件
├── requirements.txt    # Python依赖
├── Dockerfile          # Docker构建文件
└── doc/
    └── API.md          # API文档
```

## 快速开始

### 环境要求

- Python 3.11+
- pip

### 安装依赖

```bash
pip install -r requirements.txt
```

### 修改配置

编辑 `config.yaml` 文件：

```yaml
host: "0.0.0.0"
port: 5000
debug: false
heartbeat_timeout: 30.0
cleanup_interval: 10
redis_enabled: true
redis_url: "redis://redis.sothothv2-ns.svc.cluster.local:6379/0"
redis_strict_mode: true
redis_key_prefix: "secflow:menu"
health_scheduler_interval: 5
health_check_interval: 30
health_check_timeout: 2.0
health_failure_threshold: 2
service_gateway_url: "http://secflow.ai.icsl.huawei.com"
log_level: "INFO"
```

### 启动服务

```bash
python app.py --config config.yaml
```

### Docker 部署

```bash
# 构建镜像
docker build -t secflow-menu .

# 运行容器
docker run -d -p 5000:5000 -v $(pwd)/config.yaml:/app/config.yaml secflow-menu
```

## API 文档

详见 [doc/API.md](doc/API.md)

## 服务成熟度

| 成熟度 | 说明 |
|--------|------|
| 已上线 | 正式环境可用 |
| 开发中 | 开发测试中 |
| 规划中 | 规划中 |

## 其他微服务集成

其他微服务启动时需要向本服务注册，并定期发送心跳：

```python
import requests
import time

MENU_SERVICE_URL = "http://secflow-menu:5000/api/menu"

def register():
    payload = {
        "service_id": "your-service-id",
        "service_name": "您的服务",
        "host": "your-service-host",
        "port": 8080,
        "api_prefix": "/api/your-service",
        "maturity": "已上线",
        "health_check": {
            "path": "/api/your-service/health",
            "interval_seconds": 30,
            "timeout_seconds": 2
        },
        "menu_item": {
            "id": "menu-id",
            "name": "菜单名称",
            "path": "/menu-path",
            "order": 1
        }
    }
    requests.post(f"{MENU_SERVICE_URL}/register", json=payload)

def heartbeat():
    requests.post(f"{MENU_SERVICE_URL}/heartbeat/your-service-id")

# 启动时注册
register()

# 定时心跳
while True:
    heartbeat()
    time.sleep(10)
```

## 多副本机制

- `register / heartbeat / unregister` 统一写入 Redis，共享注册状态
- `GET /api/menu/services/health*` 从 Redis 读取共享健康缓存
- 多个 menu Pod 通过 Redis 锁选主，只有一个实例负责主动健康探测和过期清理
- 如果服务注册时上报了 `0.0.0.0 / 127.0.0.1`，menu 会优先使用 `service_gateway_url + api_prefix + /health` 进行探测
