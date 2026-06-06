# 数据流漏洞追踪: util_dir_exists

## 函数信息
- **文件**: src/utils/cutils/utils_file.c
- **行号**: L48-L63
- **签名**: `bool util_dir_exists(const char *path)`
- **深度**: 2/5
- **调用者**: `lcr_rt_read_pidfile` (L130, task 描述)
- **调用点父上下文污点**: `params->container_pidfile` → `path`

## 污点摘要

| # | 符号 | 类型 | 行 | 说明 |
|---|------|------|-----|------|
| INPUT-1 | `path` | param | L48 | 🔴 TAINTED - 外部控制目录路径，由 attacker 通过 name+rootpath 构造，无路径规范化 |

## 数据流树状图

### INPUT-1: path (const char*) 🔴 TAINTED
```
└── [L57] stat(path, &s) ⚠️ DIRECT_SINK / 信息泄漏
    ├── 成功路径：[L62] return S_ISDIR(s.st_mode) → 向调用方泄漏目录存在性
    └── 失败路径：stat() 返回 -1 / errno 泄漏 → [L59/L60] return false
```

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 类型 |
|--------|------|------|------|
| path | stat(path, &s) | L57 | ⚠️ DIRECT_SINK - 系统调用，泄漏目录存在性及元数据 |
| path | return S_ISDIR(s.st_mode) | L62 | ⚠️ DIRECT_SINK - 返回值向调用方泄漏目录存在性判断 |
| s (struct stat) | 结构体填充 | L57 | ⚠️ 隐式信息泄漏 - st_uid/st_gid/st_mode/st_size 等元数据 |

## 无跟入子函数

- `stat()` — 标准 POSIX 系统调用，无子函数

## 漏洞候选评估

### 漏洞候选 #1: 目录存在性枚举 / 信息泄漏
- **风险等级**: 中
- **根因**: attacker 通过控制 name+rootpath 构造任意 path，`util_dir_exists` 调用 `stat()` 检查目录存在性，返回值泄漏信息
- **触发**: attacker 构造不同的 path 值，通过观察 `util_dir_exists` 返回 true/false，枚举系统目录（如 `/proc/sys/fs/...`、挂载点等）来判断容器安全配置
- **关键代码**:
  ```c
  L57: nret = stat(path, &s);
  L62: return S_ISDIR(s.st_mode);  // 返回值泄漏目录存在性
  ```
- **影响**: 在容器化环境中，attacker 可枚举 `/var/run/`、`/sys/fs/cgroup/`、`/proc/1/root/` 等特殊路径，判断是否已挂载、是否可写入，实现侦察和信息收集

### 漏洞候选 #2: stat 结构体元数据泄漏
- **风险等级**: 低
- **根因**: 成功执行 `stat()` 后，`struct stat s` 包含目标文件的 uid/gid/mode/size/atime/mtime 等元数据
- **触发**: 若这些信息被写入日志或传递到后续逻辑，attacker 可通过 path 枚举推断文件属性
- **注意**: 当前函数内 struct stat s 为局部变量，若仅在函数内使用后销毁则风险较低；主要风险在于返回值（目录存在性）本身