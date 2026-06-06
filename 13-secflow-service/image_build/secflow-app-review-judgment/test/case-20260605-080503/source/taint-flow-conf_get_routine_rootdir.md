# 污点流: conf_get_routine_rootdir — `key` 参数深度分析

## 函数信息
- 文件: `src/daemon/config/isulad_config.c`
- 行号: L292–L346
- 签名: `char *conf_get_routine_rootdir(const char *runtime)`
- 任务参数名: `key` (= `runtime` 实参)

---

## 阶段一：识别污点源

| 参数 | 类型 | 污点标记 | 来源说明 |
|------|------|---------|---------|
| `key` → `runtime` | `const char *` | 🔴 TAINTED | 外部调用者传入的配置字符串，未经本函数验证 |

---

## 阶段二：逐行追踪传播路径

**L292**: `char *conf_get_routine_rootdir(const char *runtime)`
- 参数 `runtime` = 🔴 TAINTED

**L294**: `char *path = NULL;` → path 初始为 clean

**L299**: `if (runtime == NULL)` → NULL 检查（安全保护，无污点传播）

**L308**: `conf = conf_get_server_conf();` → conf 获取内部配置，与污点无关

**L315**: `graph_len = strlen(conf->json_confs->graph);` → 从内部配置读取，clean

**L316**: `graph_len > (SIZE_MAX - strlen(ENGINE_ROOTPATH_NAME) - strlen(runtime)) - 3`
- `strlen(runtime)` 参与 SIZE_MAX 溢出边界检查 → 防御性计算，无污点新载体产生

**L320**: `len = graph_len + 1 + strlen(ENGINE_ROOTPATH_NAME) + 1 + strlen(runtime) + 1;`
- **len** 🔴 TAINTED — `strlen(runtime)` 参与 `len` 计算，`len` 的值受污点控制

**L327**: `if (len > PATH_MAX / sizeof(char))` → 路径最大长度边界检查（防御性）

**L328**: `path = util_smart_calloc_s(sizeof(char), len);`
- **path** 🔴 TAINTED — `len` 由污点 `runtime` 控制，分配缓冲区大小受污点支配
- `path` 在此处成为 **新导入的污点载体**（output buffer 由污点数据决定大小）

**L331**: `int nret = snprintf(path, len, "%s/%s/%s", conf->json_confs->graph, ENGINE_ROOTPATH_NAME, runtime);`
- `len` 是分配大小，由污点计算得出 → ⚠️ **DIRECT_SINK**: 污点控制的缓冲区大小导致可能的分配不足
- `runtime` 被写入 `path` 缓冲区的中间段 → path 承载 runtime 内容
- `runtime` 作为 snprintf 参数传入，不构成格式字符串漏洞（格式串是字面量 `"%s/%s/%s"`）

**L332–L335**: `if (nret < 0 || (size_t)nret >= len)` → snprintf 失败检查（无新载体）

**L340**: `out: (void)isulad_server_conf_unlock();`

**L341**: `return path;` → 📌 **USED** — 污点载体作为函数返回值被调用者接收

---

## 阶段三：数据流树状图

```
### INPUT-1: runtime (const char *) 🔴 TAINTED — 外部调用者传入的配置字符串
├── [L299] if (runtime == NULL) → NULL 检查（安全保护）
├── [L316] strlen(runtime) 参与 SIZE_MAX 溢出边界检查（防御性）
└── [L320] len = graph_len + ... + strlen(runtime) + 1 → len 🔴 TAINTED
    ├── [L327] len > PATH_MAX 边界检查（防御性）
    └── [L328] util_smart_calloc_s(sizeof(char), len) → path 🔴 TAINTED
        ⚠️ DIRECT_SINK: len 由 strlen(runtime) 计算，分配缓冲区大小受污点支配
        └── [L331] snprintf(path, len, "%s/%s/%s", graph, ENGINE_ROOTPATH_NAME, runtime)
            └── path 🔴 TAINTED（承载写入的 runtime 字符串内容）
                └── [L341] return path → 📌 USED（返回给调用者）
```

---

## 阶段四：污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `runtime` | `snprintf` 参数 | L331 | runtime 被格式化写入 path，是数据最终写入点 |
| `len`（受污点控制）| `util_smart_calloc_s` 分配大小 | L328 | ⚠️ DIRECT_SINK: 分配缓冲区大小由污点控制，可能导致分配不足 |
| `path` | 函数返回值 | L341 | 📌 USED — 承载污点内容的字符串返回给调用者 |

---

## 接收此污点的子函数

| 函数 | 调用位置 | 接收的形参 | 说明 |
|------|---------|-----------|------|
| *(无内部子函数调用)* | — | — | 工具函数 `util_smart_calloc_s` 为标准库封装，不计入 |

> **函数返回值 `path` 作为污点载体被下游调用者接收**，将在以下调用点递归追踪：
> - `engines/engine.c:212` → `rootpath = conf_get_routine_rootdir(name)`
> - `lcr/lcr_rt_ops.c:69` → `runtime_root = conf_get_routine_rootdir(runtime)`
> - `executor/container_cb/execution_create.c:660`
> - `executor/container_cb/execution_create.c:1131`
> - `modules/spec/specs_mount.c:2582`
> - `modules/container/restore/restore.c:560`

---

## 高危模式标记

| 模式 | 位置 | 说明 |
|------|------|------|
| ⚠️ 污点控制的分配大小 | L328 | `len` 由 `strlen(runtime)` 决定，`util_smart_calloc_s` 分配大小受污点支配。若 runtime 超长但边界检查通过（PATH_MAX 检查前），则 `len` 仍为正确值；若 `strlen(runtime)` 返回极大值导致计算错误，结果路径长度不受控。 |
| ⚠️ 污点写入格式化输出 | L331 | `runtime` 字符串被拼接进路径，若含 `../` 等路径遍历字符，下游路径操作存在目录遍历风险。 |