# SecFlow 部署脚本管理服务 API 文档

## 服务信息

| 属性 | 值 |
|------|-----|
| 服务名称 | secflow-deploy-script |
| API 前缀 | /api/deploy-script |
| 默认端口 | 10006 |

## 认证说明

- **公开接口**（无需认证）：健康检查、就绪检查、文件列表、查看文件内容、下载文件
- **鉴权接口**（需要 Bearer Token）：上传文件、编辑文件、删除文件/目录、创建目录、重命名、批量上传

### Token 获取

调用认证服务 `/api/auth/login` 接口获取 token。

### 认证头格式

```
Authorization: Bearer <token>
```

## 接口列表

### 1. 健康检查

**GET** `/api/deploy-script/health`

检查服务是否正常运行。

**响应示例**：
```json
{
  "status": "ok",
  "service": "secflow-deploy-script-service"
}
```

---

### 2. 就绪检查

**GET** `/api/deploy-script/ready`

检查服务是否就绪（文件根目录是否存在）。

**响应示例**：
```json
{
  "status": "ready"
}
```

---

### 3. 列出目录内容

**GET** `/api/deploy-script/files{path}`

列出指定目录下的文件和子目录。

**参数**：
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| path | string | 否 | 目录路径，相对于根目录，默认根目录 |

**响应示例**：
```json
{
  "path": "/",
  "total": 5,
  "items": [
    {
      "name": "script",
      "path": "/script",
      "is_dir": true,
      "size": 0,
      "modified_at": 1704950400.0
    },
    {
      "name": "bootstrap.sh",
      "path": "/bootstrap.sh",
      "is_dir": false,
      "size": 1234,
      "modified_at": 1704950400.0
    }
  ]
}
```

---

### 4. 查看文件内容

**GET** `/api/deploy-script/files{path}/content`

查看文件内容（文本文件直接返回内容，二进制文件返回二进制流）。

**参数**：
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| path | string | 是 | 文件路径，相对于根目录 |

**响应**：文本文件返回纯文本内容，二进制文件返回 octet-stream。

---

### 5. 下载文件

**GET** `/api/deploy-script/file{path}/download`

下载文件（公开接口，无需认证）。

**参数**：
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| path | string | 是 | 文件路径，相对于根目录 |

**响应**：返回文件下载流。

---

### 6. 上传文件

**POST** `/api/deploy-script/file{path}`

上传文件（需要认证）。

**参数**：
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| path | string | 是 | 目标路径，相对于根目录（文件名从请求体获取） |
| file | File | 是 | 上传的文件内容 |

**请求格式**：multipart/form-data

**响应示例**：
```json
{
  "message": "文件上传成功",
  "path": "/test.txt",
  "filename": "test.txt",
  "size": 1024
}
```

---

### 7. 编辑文件

**PUT** `/api/deploy-script/file{path}`

编辑文件内容（需要认证）。

**参数**：
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| path | string | 是 | 文件路径，相对于根目录 |

**请求体**：
```json
{
  "content": "新的文件内容"
}
```

**响应示例**：
```json
{
  "message": "文件编辑成功",
  "path": "/test.txt"
}
```

---

### 8. 删除文件/目录

**DELETE** `/api/deploy-script/file{path}`

删除文件或目录（需要认证）。

**参数**：
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| path | string | 是 | 文件或目录路径，相对于根目录 |

**响应示例**：
```json
{
  "message": "删除成功",
  "path": "/test.txt"
}
```

> 注意：删除目录会递归删除目录下所有内容。

---

### 9. 创建目录

**POST** `/api/deploy-script/directory{path}`

创建新目录（需要认证）。

**参数**：
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| path | string | 是 | 目录路径，相对于根目录 |

**响应示例**：
```json
{
  "message": "目录创建成功",
  "path": "/new_dir"
}
```

---

### 10. 重命名

**POST** `/api/deploy-script/file{path}/rename**

重命名文件或目录（需要认证）。

**参数**：
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| path | string | 是 | 原始路径，相对于根目录 |

**请求体**：
```json
{
  "new_name": "new_name.txt"
}
```

**响应示例**：
```json
{
  "message": "重命名成功",
  "old_path": "/old_name.txt",
  "new_path": "/new_name.txt"
}
```

---

### 11. 批量上传

**POST** `/api/deploy-script/files{path}/batch`

批量上传多个文件（需要认证）。

**参数**：
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| path | string | 是 | 目标目录路径，相对于根目录 |
| files | File[] | 是 | 上传的文件列表 |

**请求格式**：multipart/form-data

**响应示例**：
```json
{
  "message": "成功上传 3 个文件",
  "total": 3,
  "results": [
    {
      "filename": "file1.txt",
      "path": "/target/file1.txt",
      "size": 1024
    },
    {
      "filename": "file2.txt",
      "path": "/target/file2.txt",
      "size": 2048
    }
  ]
}
```

---

## 错误响应

所有接口的错误响应格式：

```json
{
  "error_code": "ERROR_CODE",
  "message": "错误描述"
}
```

### 错误码列表

| 错误码 | HTTP状态码 | 说明 |
|--------|-------------|------|
| UNAUTHORIZED | 401 | 未授权访问（缺少或无效Token） |
| FORBIDDEN | 403 | 禁止访问 |
| NOT_FOUND | 404 | 资源不存在 |
| VALIDATION_ERROR | 400 | 请求参数验证错误 |
| CONFLICT | 409 | 资源冲突 |
| INTERNAL_ERROR | 500 | 内部错误 |

## 配置文件

### config.yaml

```yaml
# 应用配置
app:
  host: "0.0.0.0"
  port: 10006
  debug: false

# 文件根目录
file_root: "/app/resource"

# 认证服务配置
auth_service:
  host: "192.168.12.44"
  port: 10000
  validate_token_path: "/api/auth/validate-human-token"
  timeout: 10
  token_cache_enabled: true
  token_cache_ttl_minutes: 15

# 注册中心配置
registry:
  enabled: true
  menu_service_url: "http://192.168.12.44:10003"
  service_id: "secflow-deploy-script"
  service_name: "部署脚本管理服务"
  host: "0.0.0.0"
  port: 10006
  maturity: "已上线"
  description: "提供部署脚本的文件管理功能"
  api_prefix: "/api/deploy-script"
  menu:
    id: "deploy-script-manage"
    path: "/deploy-script"
    icon: "code"
    order: 10
    level1:
      name: "系统工具"
      name_en: "System Tools"
    level2:
      name: "部署脚本"
      name_en: "Deploy Scripts"
```

## Docker 构建

```bash
# 构建镜像
cd /path/to/secflow-platform-deploy-script
docker build -t secflow-platform-deploy-script:latest .

# 运行容器
docker run -d \
  --name secflow-deploy-script \
  -p 10006:10006 \
  -v /path/to/resource:/app/resource \
  secflow-platform-deploy-script:latest
```

## 部署到 K8S

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secflow-deploy-script
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secflow-deploy-script
  template:
    metadata:
      labels:
        app: secflow-deploy-script
    spec:
      containers:
      - name: deploy-script
        image: secflow-platform-deploy-script:latest
        ports:
        - containerPort: 10006
        volumeMounts:
        - name: resource-volume
          mountPath: /app/resource
      volumes:
      - name: resource-volume
        configMap:
          name: deploy-script-resource
---
apiVersion: v1
kind: Service
metadata:
  name: secflow-deploy-script
spec:
  selector:
    app: secflow-deploy-script
  ports:
  - port: 80
    targetPort: 10006
  type: ClusterIP
```