# Static Binary Manager API Documentation

## Overview

多架构软件包管理系统后端API，基于Flask + MySQL构建，提供软件包上传、解析、存储、管理、校验等功能。

## Base URL

```
http://{host}:8080
```

## Content-Type

All requests and responses use `application/json` unless otherwise specified.

---

## Software Package Management

### Get All Packages List

Retrieves a list of all software packages.

**Endpoint:** `GET /api/packages`

**Response:**
```json
{
  "success": true,
  "count": 10,
  "packages": [
    {
      "id": "md5_hash_string",
      "name": "nginx",
      "version": "v1.28",
      "system": "linux",
      "architecture": "armel",
      "original_filename": "nginx-v1.28-linux-armel.tar.gz",
      "total_size": 1024000,
      "file_count": 15,
      "upload_time": "2025-01-15T10:30:00",
      "last_check_time": "2025-01-15T10:30:00",
      "check_status": "valid",
      "original_package_path": "/data/packages/original_packages/xxx_nginx-v1.28-linux-armel.tar.gz",
      "download_count": 100,
      "last_download_time": "2025-01-15T12:00:00"
    }
  ]
}
```

---

### Search Packages

Search software packages by name, version, or architecture.

**Endpoint:** `GET /api/packages/search`

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| name | string | No | Package name (fuzzy match) |
| version | string | No | Version (fuzzy match) |
| architecture | string | No | CPU architecture (fuzzy match) |

**Example:**
```bash
GET /api/packages/search?name=nginx&architecture=armel
```

**Response:**
```json
{
  "success": true,
  "count": 5,
  "packages": [...]
}
```

---

### Get Package Detail

Retrieves detailed information about a specific package.

**Endpoint:** `GET /api/packages/{package_id}`

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| package_id | string | Package MD5 hash ID |

**Response:**
```json
{
  "success": true,
  "package": {
    "id": "md5_hash_string",
    "name": "nginx",
    "version": "v1.28",
    "system": "linux",
    "architecture": "armel",
    "original_filename": "nginx-v1.28-linux-armel.tar.gz",
    "storage_path": "/data/packages/md5_hash",
    "original_package_path": "/data/packages/original_packages/...",
    "total_size": 1024000,
    "file_count": 15,
    "upload_time": "2025-01-15T10:30:00",
    "last_check_time": "2025-01-15T10:30:00",
    "check_status": "valid",
    "download_count": 100,
    "last_download_time": "2025-01-15T12:00:00"
  },
  "files": [
    {
      "path": "nginx",
      "name": "nginx",
      "size": 1024000,
      "download_count": 50,
      "last_download_time": "2025-01-15T12:00:00"
    }
  ],
  "total_files": 15
}
```

---

### Get Package Files List (Pagination)

Retrieves a paginated list of files within a package.

**Endpoint:** `GET /api/packages/{package_id}/files`

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| package_id | string | Package MD5 hash ID |

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | int | 1 | Page number |
| per_page | int | 50 | Items per page |

**Response:**
```json
{
  "success": true,
  "files": [
    {
      "path": "usr/sbin/nginx",
      "name": "nginx",
      "size": 1024000,
      "storage_path": "/data/packages/xxx/usr/sbin/nginx",
      "download_count": 50,
      "last_download_time": "2025-01-15T12:00:00"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 100,
    "pages": 2
  }
}
```

---

### Upload Package

Uploads a new software package.

**Endpoint:** `POST /api/packages/upload`

**Content-Type:** `multipart/form-data`

**Form Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| file | file | Yes | Package file (.zip, .tar.gz, .tar.bz2, etc.) |

**Filename Format:**
```
{name}-{version}-linux-{architecture}.{extension}
```

Examples:
- `nginx-v1.28-linux-armel.tar.gz`
- `redis-v6.2-linux-x86_64.tar.gz`

**Response:**
```json
{
  "success": true,
  "package_id": "md5_hash_string",
  "package_info": {
    "name": "nginx",
    "version": "v1.28",
    "system": "linux",
    "architecture": "armel"
  },
  "storage_path": "/data/packages/md5_hash",
  "original_package_path": "/data/packages/original_packages/...",
  "total_size": 1024000,
  "file_count": 15
}
```

**Error Response (Duplicate):**
```json
{
  "success": false,
  "error": "相同的软件包已存在（文件内容相同）",
  "package_id": "md5_hash"
}
```

---

### Check Package Integrity

Verifies the integrity of a package by checking file existence and size.

**Endpoint:** `GET /api/packages/{package_id}/check`

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| package_id | string | Package MD5 hash ID |

**Response:**
```json
{
  "success": true,
  "valid": true,
  "missing_files": [],
  "size_mismatch_files": [],
  "total_files": 15,
  "checked_files": 15,
  "check_time": "2025-01-15T12:00:00",
  "package_id": "md5_hash",
  "package_name": "nginx-v1.28"
}
```

---

### Batch Check All Packages

Performs integrity check on all packages.

**Endpoint:** `POST /api/packages/check-all`

**Response:**
```json
{
  "success": true,
  "total": 10,
  "results": [
    {
      "valid": true,
      "package_id": "md5_hash",
      "package_name": "nginx-v1.28"
    }
  ]
}
```

---

### Delete Package

Deletes a single package.

**Endpoint:** `DELETE /api/packages/{package_id}`

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| package_id | string | Package MD5 hash ID |

**Response:**
```json
{
  "success": true,
  "message": "软件包删除成功",
  "package_id": "md5_hash"
}
```

---

### Batch Delete Packages

Batch delete multiple packages by IDs.

**Endpoint:** `POST /api/packages/batch-delete`

**Request Body:**
```json
{
  "package_ids": ["md5_hash_1", "md5_hash_2", "md5_hash_3"]
}
```

**Response:**
```json
{
  "success": true,
  "message": "批量删除完成，成功: 3, 失败: 0",
  "success_count": 3,
  "error_count": 0
}
```

---

### Delete All Packages

Deletes all packages (use with caution).

**Endpoint:** `DELETE /api/packages/delete-all`

**Response:**
```json
{
  "success": true,
  "message": "已删除所有软件包，共 10 个"
}
```

---

## Download APIs

### Download Original Package

Downloads the original package file.

**Endpoint:** `GET /api/packages/{package_id}/download`

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| package_id | string | Package MD5 hash ID |

**Response:** File download (octet-stream)

---

### Download Package Sub-file

Downloads a specific file from within a package.

**Endpoint:** `GET /api/packages/{package_id}/files/download`

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| package_id | string | Package MD5 hash ID |

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| path | string | Yes | File path within package |

**Example:**
```bash
GET /api/packages/md5_hash/files/download?path=usr/sbin/nginx
```

**Response:** File download (octet-stream)

---

### Download Latest Package by Conditions

Downloads the latest package based on system, architecture, and name.

**Endpoint:** `GET /api/packages/download/latest`

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| system | string | Yes | Operating system (e.g., "linux") |
| architecture | string | Yes | CPU architecture (e.g., "armel") |
| name | string | Yes | Package name (exact match) |

**Example:**
```bash
GET /api/packages/download/latest?system=linux&architecture=armel&name=nginx
```

**Response:** File download (octet-stream)

---

### Redirect to Latest Package

Redirects to the latest package file (302 redirect).

**Endpoint:** `GET /api/packages/download/latest/redirect`

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| system | string | Yes | Operating system |
| architecture | string | Yes | CPU architecture |
| name | string | Yes | Package name |

**Response:** 302 Redirect to nginx static path

---

### Download File by Conditions

Downloads a file based on system, architecture, filename, and optional package name.

**Endpoint:** `GET /api/packages/files/download/by-conditions`

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| system | string | Yes | Operating system |
| architecture | string | Yes | CPU architecture |
| filename | string | Yes | Filename (without path, exact match) |
| name | string | No | Package name |

**Example:**
```bash
GET /api/packages/files/download/by-conditions?system=linux&architecture=armel&filename=nginx&name=nginx
```

**Response:** File download (octet-stream)

If multiple matches found:
```json
{
  "success": true,
  "message": "找到3个匹配的文件，请指定具体的软件包或路径",
  "count": 3,
  "files": [...]
}
```

---

### Redirect to File by Conditions

Redirects to file by conditions (302 redirect).

**Endpoint:** `GET /api/packages/files/download/by-conditions/redirect`

**Query Parameters:** Same as above, plus:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| force | boolean | No | When `true`, if multiple files match, auto-select the latest and best-matched file and redirect directly |

**Response:** 302 Redirect to nginx static path.  
If multiple matches and `force` is not true, returns JSON list.

---

## Search APIs

### Search Files in Package

Searches for files within packages by filename.

**Endpoint:** `GET /api/packages/files/search`

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| filename | string | Yes | Filename to search (fuzzy match) |

**Example:**
```bash
GET /api/packages/files/search?filename=nginx
```

**Response:**
```json
{
  "success": true,
  "count": 2,
  "total_matches": 5,
  "packages": [
    {
      "id": "md5_hash",
      "name": "nginx",
      "version": "v1.28",
      "system": "linux",
      "architecture": "armel",
      "matched_files_count": 3,
      "matched_files": [
        {
          "file_path": "usr/sbin/nginx",
          "file_name": "nginx",
          "file_size": 1024000
        }
      ]
    }
  ]
}
```

---

## Statistics APIs

### Get Statistics

Retrieves overall statistics about the package system.

**Endpoint:** `GET /api/packages/statistics`

**Response:**
```json
{
  "success": true,
  "statistics": {
    "summary": {
      "total_packages": 100,
      "total_size": 10737418240,
      "total_size_human": "10.00 GB",
      "total_files": 1500,
      "total_downloads": 5000,
      "avg_file_size": 7158278.23,
      "avg_package_size": 107374182.40
    },
    "most_downloaded": {
      "package_id": "md5_hash",
      "name": "nginx",
      "version": "v1.28",
      "download_count": 1000,
      "architecture": "armel"
    },
    "by_architecture": [
      {
        "architecture": "armel",
        "package_count": 30,
        "total_size": 3221225472,
        "total_size_human": "3.00 GB",
        "download_count": 1500
      }
    ],
    "by_system": [
      {
        "system": "linux",
        "package_count": 100,
        "total_size": 10737418240,
        "total_size_human": "10.00 GB",
        "download_count": 5000
      }
    ],
    "by_status": [
      {
        "status": "valid",
        "package_count": 95,
        "download_count": 4750
      }
    ]
  }
}
```

---

### Query Statistics by Conditions

Queries statistics based on filter conditions.

**Endpoint:** `GET /api/packages/statistics/query`

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| architecture | string | Filter by CPU architecture |
| system | string | Filter by operating system |
| check_status | string | Filter by check status (pending, checking, valid, invalid) |
| name | string | Filter by package name |
| version | string | Filter by version |

**Response:**
```json
{
  "success": true,
  "statistics": {
    "summary": {
      "package_count": 50,
      "file_count": 750,
      "total_size": 5368709120,
      "total_size_human": "5.00 GB",
      "total_downloads": 2500,
      "avg_file_size": 7158278.23,
      "avg_file_size_human": "6.83 MB"
    },
    "by_architecture": [...],
    "by_system": [...],
    "by_check_status": [...]
  },
  "query_conditions": {
    "architecture": "armel",
    "system": "linux",
    "check_status": "valid",
    "name": "nginx",
    "version": "v1.28"
  }
}
```

---

### Get Detailed Statistics

Retrieves detailed statistics grouped by a specific dimension.

**Endpoint:** `GET /api/packages/statistics/detailed`

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| group_by | string | architecture | Grouping dimension (architecture, system, check_status) |

**Example:**
```bash
GET /api/packages/statistics/detailed?group_by=architecture
```

**Response:**
```json
{
  "success": true,
  "group_by": "architecture",
  "summary": {
    "total_packages": 100,
    "total_files": 1500,
    "total_size": 10737418240,
    "total_size_human": "10.00 GB",
    "total_downloads": 5000
  },
  "details": [
    {
      "group": "armel",
      "package_count": 30,
      "file_count": 450,
      "total_size": 3221225472,
      "total_size_human": "3.00 GB",
      "download_count": 1500,
      "avg_package_size": 107374182.40,
      "avg_package_files": 15.0
    }
  ]
}
```

---

## Utility APIs

### Get Supported Architectures

Retrieves a list of all CPU architectures currently in the system.

**Endpoint:** `GET /api/packages/architectures`

**Response:**
```json
{
  "success": true,
  "architectures": [
    "aarch64",
    "arm64",
    "armel",
    "armhf",
    "i386",
    "i686",
    "mips",
    "mips64",
    "ppc64",
    "ppc64le",
    "s390x",
    "x86",
    "x86_64"
  ]
}
```

---

### Health Check

Checks the health status of the service.

**Endpoint:** `GET /api/packages/health`

**Response (Healthy):**
```json
{
  "status": "healthy",
  "database": "connected",
  "storage": "available",
  "original_storage": "available",
  "timestamp": "2025-01-15T12:00:00"
}
```

**Response (Unhealthy):**
```json
{
  "status": "unhealthy",
  "error": "Database connection failed"
}
```

---

## Data Models

### Package Model

| Field | Type | Description |
|-------|------|-------------|
| id | string | MD5 hash (primary key) |
| name | string | Package name |
| version | string | Version number |
| system | string | Operating system (default: "linux") |
| architecture | string | CPU architecture |
| original_filename | string | Original uploaded filename |
| storage_path | string | Path to extracted package |
| original_package_path | string | Path to original compressed file |
| total_size | bigint | Total size in bytes |
| file_count | int | Number of files |
| upload_time | datetime | Upload timestamp |
| last_check_time | datetime | Last integrity check timestamp |
| check_status | string | Check status (pending, checking, valid, invalid) |
| download_count | int | Download count |
| last_download_time | datetime | Last download timestamp |

### PackageFile Model

| Field | Type | Description |
|-------|------|-------------|
| id | int | Auto-increment ID |
| package_id | string | Foreign key to Package |
| file_path | string | Relative file path within package |
| file_name | string | Filename (without path) |
| file_size | bigint | File size in bytes |
| storage_path | string | Actual storage path |
| download_count | int | Download count |
| last_download_time | datetime | Last download timestamp |

---

## Supported CPU Architectures

- `x86_64` / `amd64` / `x86` / `i386` / `i686`
- `arm64` / `aarch64` / `armhf` / `armel`
- `ppc64le` / `ppc64` / `s390x`
- `mips` / `mips64`

---

## Supported File Formats

**Compression Formats:**
- `.zip`
- `.tar.gz`
- `.tar.bz2`
- `.tar.xz`
- `.tar`
- `.gz`
- `.bz2`

**Maximum Upload Size:** 2GB

---

## Error Responses

All error responses follow this format:

```json
{
  "success": false,
  "error": "Error description"
}
```

**HTTP Status Codes:**
- `400` - Bad Request (missing required parameters)
- `403` - Forbidden (path security violation)
- `404` - Not Found (resource doesn't exist)
- `409` - Conflict (duplicate package)
- `500` - Internal Server Error
