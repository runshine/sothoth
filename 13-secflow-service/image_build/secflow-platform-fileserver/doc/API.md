# SecFlow File Server API 文档

## API 汇总

所有 API 都以 `/api/fileserver` 为前缀。

| 序号 | 方法 | 接口路径 | 说明 |
|------|------|----------|------|
| 1 | GET | `/api/fileserver/health` | 健康检查 |
| 2 | GET | `/api/fileserver/ready` | 就绪检查 |
| 3 | POST | `/api/fileserver/subprojects` | 创建子项目 |
| 4 | GET | `/api/fileserver/subprojects?project_id={project_id}` | 查询子项目列表 |
| 5 | GET | `/api/fileserver/subprojects/{subproject_id}?project_id={project_id}` | 查询单个子项目 |
| 6 | PUT | `/api/fileserver/subprojects/{subproject_id}?project_id={project_id}` | 修改子项目 |
| 7 | DELETE | `/api/fileserver/subprojects/{subproject_id}?project_id={project_id}` | 删除空子项目 |
| 8 | POST | `/api/fileserver/directories` | 创建目录 |
| 9 | GET | `/api/fileserver/directories/tree?project_id={project_id}&subproject_id={subproject_id}` | 查询目录树 |
| 10 | POST | `/api/fileserver/files/upload` | 上传文件 |
| 11 | GET | `/api/fileserver/files?project_id={project_id}&subproject_id={subproject_id}&directory_id={directory_id}` | 查询目录下文件 |
| 12 | GET | `/api/fileserver/files/{file_id}` | 查询文件详情 |
| 13 | GET | `/api/fileserver/files/{file_id}/download` | 下载文件 |
| 14 | POST | `/api/fileserver/files/{file_id}/rename` | 重命名文件 |
| 15 | POST | `/api/fileserver/files/{file_id}/move` | 移动文件 |
| 16 | DELETE | `/api/fileserver/files/{file_id}` | 删除文件 |

## 概述

文件管理服务用于按 `项目 -> 子项目 -> 目录 -> 文件` 的逻辑层级管理共享存储中的文件。

核心特性：

- 使用 MySQL 保存元数据
- 使用 RWX PVC 保存文件内容
- 物理路径采用 `/data/files/{project_id}/{subproject_id}/{logical_path}/{original_filename}`
- 所有 Pod 无状态，可多副本部署
- 调用 `secflow-platform-auth` 做用户 Token 校验
- 调用 `secflow-platform-project` 做项目访问权限校验

## 认证

除健康检查外，所有接口都需要在请求头携带人机 Token：

```http
Authorization: Bearer <human_token>
```

## 1. 子项目管理

### 1.1 创建子项目

```http
POST /api/fileserver/subprojects
Content-Type: application/json
Authorization: Bearer <token>
```

请求体：

```json
{
  "project_id": "2abc83006a7ca7a4",
  "name": "delivery-package",
  "description": "交付物目录"
}
```

响应：

```json
{
  "id": 1,
  "project_id": "2abc83006a7ca7a4",
  "name": "delivery-package",
  "description": "交付物目录",
  "created_by": "1",
  "created_at": "2026-03-24T18:00:00",
  "updated_at": "2026-03-24T18:00:00"
}
```

### 1.2 查询子项目列表

```http
GET /api/fileserver/subprojects?project_id=2abc83006a7ca7a4
Authorization: Bearer <token>
```

响应：

```json
{
  "total": 1,
  "items": [
    {
      "id": 1,
      "project_id": "2abc83006a7ca7a4",
      "name": "delivery-package",
      "description": "交付物目录",
      "created_by": "1",
      "created_at": "2026-03-24T18:00:00",
      "updated_at": "2026-03-24T18:00:00"
    }
  ]
}
```

## 2. 目录管理

### 2.1 创建目录

```http
POST /api/fileserver/directories
Content-Type: application/json
Authorization: Bearer <token>
```

请求体：

```json
{
  "project_id": "2abc83006a7ca7a4",
  "subproject_id": 1,
  "parent_id": null,
  "name": "docs"
}
```

响应：

```json
{
  "id": 1,
  "project_id": "2abc83006a7ca7a4",
  "subproject_id": 1,
  "parent_id": null,
  "name": "docs",
  "path_key": "/docs",
  "created_by": "1",
  "created_at": "2026-03-24T18:00:00",
  "updated_at": "2026-03-24T18:00:00"
}
```

### 2.2 查询目录树

```http
GET /api/fileserver/directories/tree?project_id=2abc83006a7ca7a4&subproject_id=1
Authorization: Bearer <token>
```

响应：

```json
{
  "total": 1,
  "items": [
    {
      "id": 1,
      "name": "docs",
      "path_key": "/docs",
      "parent_id": null,
      "children": []
    }
  ]
}
```

## 3. 文件管理

### 3.1 上传文件

```http
POST /api/fileserver/files/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data
```

表单字段：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| project_id | string | 是 | 项目 ID |
| subproject_id | integer | 是 | 子项目 ID |
| directory_id | integer | 否 | 目录 ID，为空表示上传到子项目根目录 |
| file | file | 是 | 上传文件 |

示例：

```bash
curl -X POST http://127.0.0.1:18082/api/fileserver/files/upload \
  -H "Authorization: Bearer <token>" \
  -F "project_id=2abc83006a7ca7a4" \
  -F "subproject_id=1" \
  -F "directory_id=1" \
  -F "file=@./readme.txt;type=text/plain"
```

响应：

```json
{
  "id": 1,
  "project_id": "2abc83006a7ca7a4",
  "subproject_id": 1,
  "directory_id": 1,
  "filename": "readme.txt",
  "original_filename": "readme.txt",
  "content_type": "text/plain",
  "size": 128,
  "sha256": "xxxx",
  "storage_key": "files/2abc83006a7ca7a4/1/docs/readme.txt",
  "created_by": "1",
  "created_at": "2026-03-24T18:00:00",
  "updated_at": "2026-03-24T18:00:00"
}
```

### 3.2 查询文件列表

```http
GET /api/fileserver/files?project_id=2abc83006a7ca7a4&subproject_id=1&directory_id=1
Authorization: Bearer <token>
```

响应：

```json
{
  "total": 1,
  "items": [
    {
      "id": 1,
      "project_id": "2abc83006a7ca7a4",
      "subproject_id": 1,
      "directory_id": 1,
      "filename": "readme.txt",
      "original_filename": "readme.txt",
      "content_type": "text/plain",
      "size": 128,
      "sha256": "xxxx",
      "storage_key": "files/2abc83006a7ca7a4/1/docs/readme.txt",
      "created_by": "1",
      "created_at": "2026-03-24T18:00:00",
      "updated_at": "2026-03-24T18:00:00"
    }
  ]
}
```

### 3.3 下载文件

```http
GET /api/fileserver/files/{file_id}/download
Authorization: Bearer <token>
```

响应：直接返回二进制文件流。

### 3.4 重命名文件

```http
POST /api/fileserver/files/{file_id}/rename
Content-Type: application/json
Authorization: Bearer <token>
```

请求体：

```json
{
  "filename": "release-notes.txt"
}
```

### 3.5 移动文件

```http
POST /api/fileserver/files/{file_id}/move
Content-Type: application/json
Authorization: Bearer <token>
```

请求体：

```json
{
  "target_directory_id": 2
}
```

### 3.6 删除文件

```http
DELETE /api/fileserver/files/{file_id}
Authorization: Bearer <token>
```

响应：

```json
{
  "message": "文件删除成功"
}
```

## 4. 健康检查

### 4.1 健康检查

```http
GET /api/fileserver/health
```

响应：

```json
{
  "status": "ok",
  "service": "secflow-platform-fileserver"
}
```

### 4.2 就绪检查

```http
GET /api/fileserver/ready
```

响应：

```json
{
  "status": "ready"
}
```
