# Code Server Manager

基于FastAPI的Code Server管理微服务，用于在K8S环境中创建、销毁、重建code-server（VSCode Web版）实例，支持源码在线审计。

## 功能特性

1. **Code Server实例管理**
   - 创建、销毁、重建实例
   - 状态查询与监控
   - 运行日志查看

2. **PVC管理**
   - 源码PVC挂载（必须存在）
   - 输出PVC自动创建（可选）

3. **异步任务**
   - 所有操作均为异步执行（后台多线程）
   - 任务状态查询
   - 任务历史管理

4. **K8S集成**
   - Deployment管理
   - Service自动创建
   - Ingress动态生成（支持TLS）

## 项目结构

```
vscode-web-manager/
├── app/
│   ├── __init__.py
│   ├── main.py              # 应用入口
│   ├── config.py            # 配置管理
│   ├── model.py             # 数据库模型
│   ├── schemas.py           # Pydantic模型
│   ├── exception.py         # 异常定义
│   ├── api/
│   │   ├── __init__.py
│   │   └── code_server.py   # API路由
│   └── services/
│       ├── __init__.py
│       ├── k8s.py           # K8S服务
│       └── task_manager.py  # 任务管理器
├── config.yaml              # 配置文件
├── requirements.txt         # 依赖
├── Dockerfile              # 容器镜像
└── start.sh                # 启动脚本
```

## 安装与运行

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置

编辑 `config.yaml`：

```yaml
# 数据库配置（支持mysql和sqlite）
database:
  type: "sqlite"  # 或 "mysql"
  path: "./codeserver_manager.db"  # SQLite路径
  # MySQL配置
  host: "localhost"
  port: 3306
  username: "root"
  password: ""
  name: "codeserver_manager"

# Kubernetes配置
kubernetes:
  in_cluster: false  # true表示在K8S内运行
  kubeconfig: "~/.kube/config"  # 集群外运行时使用

# Code Server配置
code_server:
  image: "codercom/code-server:latest"
  service_type: "ClusterIP"  # ClusterIP, NodePort, LoadBalancer

# PVC配置
pvc:
  storage_class: "standard"
  storage_size: "5Gi"

# Ingress配置
ingress:
  base_domain: "code-server.sothothv2.com"
  tls_secret_name: "wildcard-code-server.sothothv2.com-tls"
```

### 3. 启动服务

```bash
# 直接运行
python app/main.py

# 或使用uvicorn
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload

# 或使用启动脚本
./start.sh
```

### 4. Docker运行

```bash
docker build -t code-server-manager .
docker run -p 8080:8080 -v ~/.kube/config:/root/.kube/config code-server-manager
```

## API接口

所有API前缀：`/api/app/code-server`

### Code Server管理

#### 创建Code Server
```http
POST /api/app/code-server/projects/{project_id}/code-servers
Content-Type: application/json

{
    "name": "audit-project-1",
    "namespace": "secflow-abc123",
    "description": "审计项目1",
    "source_pvcs": [
        {"pvc_name": "source-code", "mount_path": "/home/coder/project"}
    ],
    "output_pvcs": [
        {"pvc_name": "output-data", "mount_path": "/output"}
    ],
    "custom_env": {
        "MY_VAR": "value"
    }
}
```

**响应：**
```json
{
    "message": "Code Server创建任务已提交",
    "task_id": "a1b2c3d4e5f6g7h8",
    "task_type": "create"
}
```

#### 删除Code Server
```http
DELETE /api/app/code-server/projects/{project_id}/code-servers
Content-Type: application/json

{
    "name": "audit-project-1",
    "delete_output_pvcs": false
}
```

#### 重建Code Server
```http
POST /api/app/code-server/projects/{project_id}/code-servers/restart
Content-Type: application/json

{
    "name": "audit-project-1"
}
```

#### 查询Code Server列表
```http
GET /api/app/code-server/projects/{project_id}/code-servers
```

#### 查询单个Code Server
```http
GET /api/app/code-server/projects/{project_id}/code-servers/{name}
```

#### 获取实时状态
```http
GET /api/app/code-server/projects/{project_id}/code-servers/{name}/status
```

**响应：**
```json
{
    "id": "a1b2c3d4e5f6g7h8",
    "name": "audit-project-1",
    "namespace": "secflow-abc123",
    "status": "running",
    "pod_status": "Running",
    "pod_ip": "10.42.0.15",
    "node_name": "node-1",
    "access_url": "https://a1b2c3d4e5f6g7h8.code-server.sothothv2.com",
    "ready_replicas": 1,
    "total_replicas": 1
}
```

#### 获取运行日志
```http
GET /api/app/code-server/projects/{project_id}/code-servers/{name}/logs?tail_lines=100&container=
```

**响应：**
```json
{
    "code_server_id": "a1b2c3d4e5f6g7h8",
    "code_server_name": "audit-project-1",
    "namespace": "secflow-abc123",
    "pod_name": "code-server-audit-project-1-xxx",
    "container": null,
    "logs": "[2024-01-01 10:00:00] INFO: Starting code-server..."
}
```

### 任务管理

#### 查询任务列表
```http
GET /api/app/code-server/projects/{project_id}/tasks?status=&type=
```

#### 查询任务详情
```http
GET /api/app/code-server/projects/{project_id}/tasks/{task_id}
```

#### 删除任务
```http
DELETE /api/app/code-server/projects/{project_id}/tasks/{task_id}
```

### 健康检查

```http
GET /health
GET /ready
```

## 配置说明

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `database.type` | 数据库类型 | `sqlite` |
| `database.path` | SQLite数据库路径 | `./codeserver_manager.db` |
| `kubernetes.in_cluster` | 是否在K8S内运行 | `false` |
| `kubernetes.kubeconfig` | kubeconfig路径 | `~/.kube/config` |
| `code_server.image` | Code Server镜像 | `codercom/code-server:latest` |
| `code_server.image_pull_policy` | 镜像拉取策略 | `Always` |
| `code_server.service_type` | Service类型 | `ClusterIP` |
| `code_server.service_port` | 服务端口 | `80` |
| `code_server.env` | 默认环境变量 | ANTHROPIC_*等 |
| `pvc.storage_class` | PVC StorageClass | `standard` |
| `pvc.storage_size` | PVC大小 | `5Gi` |
| `ingress.base_domain` | Ingress基础域名 | `code-server.sothothv2.com` |
| `ingress.tls_secret_name` | TLS证书Secret | `wildcard-code-server.sothothv2.com-tls` |
| `tasks.retention_days` | 任务保留天数 | `7` |
| `logging.level` | 日志级别 | `INFO` |

## 开发说明

### 添加新的API

在 `app/api/code_server.py` 中添加路由：

```python
@router.post("/projects/{project_id}/custom-action")
async def custom_action(
    project_id: str = Path(...),
    db: Session = Depends(get_db)
):
    # 实现逻辑
    pass
```

### 任务处理

任务在后台线程中执行，通过TaskManager管理：
- `create_task()` - 创建新任务
- `_handle_create_task()` - 处理创建任务
- `_handle_delete_task()` - 处理删除任务
- `_handle_restart_task()` - 处理重建任务

## 注意事项

1. **Namespace必须存在** - 创建时会检查，不存在则报错
2. **源码PVC必须存在** - 创建时会检查，不存在则报错
3. **输出PVC可选** - 如果不存在会自动创建
4. **异步任务** - 创建/删除/重建都是异步的，需要通过任务ID查询状态
5. **任务保留** - 完成的任务默认保留7天，自动清理

## License

MIT
