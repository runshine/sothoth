# 数据流追踪: util_mkdir_p — 参数 `说明:`

## 函数信息
- 文件: src/utils/cutils/utils_file.c
- 行号: L255（L255-L256 为入口函数；实际逻辑在 L194-L253 `util_mkdir_p_userns_remap`）
- 签名: `int util_mkdir_p(const char *dir, mode_t mode)`

## 污点源

| ID | 参数 | 类型 | 说明 |
|----|------|------|------|
| INPUT-1 | `dir` | `const char *` | 🔴 TAINTED — 调用者传入的路径字符串，来源未经验证 |

## 数据流树状图

### INPUT-1: dir (const char *) 🔴 TAINTED
├── [L207] `if (dir == NULL || strlen(dir) > PATH_MAX)` → 仅做空值/长度检查，**内容未清洗**
│   └── [L207] `strlen(dir)` 使用污点长度值（读取边界检查，非直接复制）
├── [L215] `tmp_pos = dir` → `tmp_pos` 🔴 TAINTED（指针别名）
├── [L216] `base = dir` → `base` 🔴 TAINTED（指针别名）
└── [L217-L253] **循环体 do-while**
    ├── [L218] `tmp_pos = dir + strspn(tmp_pos, "/")` → 推进指针（标准库函数，跳过）
    ├── [L219] `tmp_pos = dir + strcspn(dir, "/")` → 推进指针（标准库函数，跳过）
    ├── [L220] `len = (int)(dir - base)` → `len` 🔴 TAINTED **（指针差值依赖污点指针）**
    ├── [L223] `cur_dir = strndup(base, (size_t)len)` ⚠️ DIRECT_SINK
    │   └── **污点长度值 len 直接控制 strndup 复制字节数**
    ├── [L231] `mkdir(cur_dir, mode)` ⚠️ DIRECT_SINK
    │   └── **污点路径片段 cur_dir（由 strndup 基于污点 len 构造）传入 mkdir 系统调用**
    ├── [L233] `if (ret != 0 && (errno != EEXIST || !util_dir_exists(cur_dir)))`
    │   └── `util_dir_exists(cur_dir)` — 目录存在性只读查询，cur_dir 仍是 🔴 TAINTED
    └── [L237] `chown(cur_dir, host_uid, host_gid)` — 条件分支，受 ret 值保护，但 cur_dir 仍为 🔴 TAINTED
├── [L252] `chmod(base, mode)` ⚠️ DIRECT_SINK
│   └── **全路径 base（复制自污点 dir）传入 chmod 系统调用**
└── [L254] `return 0` / [L255] `return -1` — 返回状态码，干净

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `dir` | ⚠️ DIRECT_SINK: `strndup(base, (size_t)len)` | L223 | 污点指针差值 len 直接控制复制字节数，可能导致缓冲区越界读取 |
| `cur_dir`（新引入 tainted carrier，由 dir 经 strndup 构造） | ⚠️ DIRECT_SINK: `mkdir(cur_dir, mode)` | L231 | 污点路径片段传入 mkdir，在文件系统创建任意目录（路径遍历风险） |
| `dir` / `base` | ⚠️ DIRECT_SINK: `chmod(base, mode)` | L252 | 污点路径传入 chmod，对构造的路径设置文件权限 |

## 关键危险分析

### 1. strndup 污点大小参数（L223）
`len = (int)(dir - base)` 的值完全由输入字符串 `dir` 的结构决定。若攻击者构造特殊路径（如大量 `../`），指针差值可能超出预期，产生非预期的内存读取。

### 2. mkdir 路径遍历（L231）
循环通过指针推进从 `dir` 提取路径片段。当前实现不验证路径组件的语义，攻击者可利用 `..` 等特殊序列逃离预期根目录，调用 `mkdir` 在任意位置创建目录。

### 3. chmod 全路径攻击（L252）
循环结束后对全路径 `base`（即原始 `dir` 的副本）执行 `chmod`，不区分循环中已创建的目录与最终目录。若路径包含遍历序列，最终 `chmod` 作用于意外目录。

## 子函数跟入列表

> **核心规则：只有 dir（及其派生值）实际作为参数传入子函数时才记录。**

| 目标 | 文件:行号 | 传入参数 | 原因 |
|------|---------|---------|------|
| `util_mkdir_p_userns_remap` | src/utils/cutils/utils_file.c:L194 | `dir`（原样传入） | 污点参数 dir 直接作为第一个参数 |

> **不记录**：`util_dir_exists` — 纯只读查询，不参与污点传播链（只是条件判断）
> **不记录**：`util_parse_user_remap` — 接收 `userns_remap` 参数，非 `dir`
> **不记录**：标准库 `strndup`/`strspn`/`strcspn`/`strlen` — 标准库函数，直接标记为 `🟡 EXPORT`

## 跟入列表（gen_tainted_list 格式）

```
src/utils/cutils/utils_file.c###util_mkdir_p_userns_remap###L194###dir
```