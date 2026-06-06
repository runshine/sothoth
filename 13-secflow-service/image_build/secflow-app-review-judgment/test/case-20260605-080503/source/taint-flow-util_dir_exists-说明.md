# Taint Analysis Report: util_dir_exists - 说明

## Function Information
- **File**: `src/utils/cutils/utils_file.c`
- **Line Range**: L48-L60
- **Signature**: `bool util_dir_exists(const char *path)`

## Tainted Parameter
- **说明:** (External input parameter) - `path` (const char*)

## Taint Flow Analysis

### Phase 1: Initial Tainted Inputs

| # | Parameter | Type | Source | Status |
|---|-----------|------|--------|--------|
| 1 | `path` | const char* | 外部输入路径参数 | 🔴 TAINTED |

### Phase 2: Line-by-Line Propagation

| Line | Code | Operation | Result | Notes |
|------|------|-----------|--------|-------|
| L50-52 | `if (path == NULL) { return false; }` | NULL检查 | 无传播 | 条件判断，不涉及污点传播 |
| L54 | `nret = stat(path, &s);` | 传入标准库函数 | ⚠️ DIRECT_SINK | `stat()` 使用污点 `path` 作为文件系统查询路径，可被利用探测任意文件/目录元数据 |
| L55-57 | `if (nret < 0) { return false; }` | 返回值检查 | 🟢 CLEANED | nret是stat()的整型返回值，无污点 |
| L59 | `return S_ISDIR(s.st_mode);` | 返回布尔值 | 🟢 CLEANED | s.st_mode由stat()填充，非用户输入污染 |

### Phase 3: Data Flow Tree

```
### INPUT-1: path (const char*) 🔴 TAINTED - 外部输入路径参数
└── [L54] nret = stat(path, &s)
    ├── ⚠️ DIRECT_SINK: stat() 使用污点 path 作为文件系统路径进行查询
    └── [L55-57] nret < 0 检查 → nret 🔴 TAINTED (return status, still tainted)
        └── [L59] return S_ISDIR(s.st_mode) → 🟢 CLEANED
```

### Phase 4: Taint Sinks

| Sink Type | Location | Description |
|-----------|----------|-------------|
| ⚠️ DIRECT_SINK | L54 | `stat(path, &s)` - 污点路径参数直接作为文件系统查询路径，可能导致敏感文件元数据泄露（如通过 path traversal 探测 /etc/passwd、/proc 等） |

### Phase 5: Sub-function Callees

| File | Function | Line | Tainted Parameters | Notes |
|------|----------|------|-------------------|-------|
| - | `stat()` | L54 | `path` | 标准C库函数 → 🟡 EXPORT |

### Phase 6: New Tainted Carriers

无新导入的 tainted carrier - struct stat s 仅用于提取 st_mode 位字段，未被返回或进一步传播污点。

## Summary

- **Leaf Function**: 否 (调用标准库 stat)
- **Tainted Parameters Received**: 1 (`path`)
- **Direct Sinks**: 1 (L54: stat() filesystem path probe)
- **New Tainted Carriers**: 0
- **Security Risk**: 高 - 污点路径可用于探测文件系统结构和敏感文件元数据