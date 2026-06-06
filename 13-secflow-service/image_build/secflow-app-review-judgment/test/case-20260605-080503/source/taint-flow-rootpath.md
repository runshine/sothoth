# 污点流: rootpath

## 污点源
- rootpath (const char *path) 🔴 TAINTED — 外部输入参数，来自调用者 `new_engine_locked()` 中的 `conf_get_routine_rootdir(name)`

## 新导入的污点对象
- tmp_path 🔴 TAINTED — 由 `util_strdup_s(path)` 在 L153 复制 rootpath 生成，继承所有污点风险

## 传播路径

### INPUT-1: rootpath (const char *path) 🔴 TAINTED
```
├── [L126] if (path == NULL) { goto out; }
│   └── 条件判断，无污点传播
├── [L130] util_dir_exists(path) → 📎 子函数
│   └── 污点路径作为目录存在性检查参数
├── [L141] ⚠️ DIRECT_SINK: util_mkdir_p(path, mode)
│   └── 污点路径直接控制目录创建路径
├── [L147] ⚠️ DIRECT_SINK: set_file_owner_for_userns_remap(path, userns_remap)
│   └── 污点路径直接控制文件所有权修改目标
├── [L153] tmp_path = util_strdup_s(path) → tmp_path 🔴 TAINTED
│   └── 复制污点路径生成新污点载体
│       ├── [L154] p = strrchr(tmp_path, '/') → p 🔴 TAINTED
│       ├── [L156] if (p == NULL) 检查
│       ├── [L157] *p = '\0' → ⚠️ DIRECT_SINK: 直接修改 tmp_path 内存
│       ├── [L161] ⚠️ DIRECT_SINK: set_file_owner_for_userns_remap(tmp_path, userns_remap)
│       │   └── 新污点载体控制父目录 chown
│       └── [L165] ERROR("...", tmp_path) → 污点进入日志
└── [L170] return ret → 📌 USED (函数返回值)
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|-----------|
| util_dir_exists | L130 | path |
| util_mkdir_p | L141 | dir |
| set_file_owner_for_userns_remap | L147 | filename |
| util_strdup_s | L153 | src |
| set_file_owner_for_userns_remap | L161 | filename |

> 注: `strrchr` 为标准 C 库函数 → 🟡 EXPORT，不列入跟入表  
> `util_strdup_s` 已找到定义（`src/utils/cutils/utils_string.c:L295`）→ 需跟入