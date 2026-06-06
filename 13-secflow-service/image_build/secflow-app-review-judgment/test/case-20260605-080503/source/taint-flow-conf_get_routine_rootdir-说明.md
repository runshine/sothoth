# 污点流: conf_get_routine_rootdir — 参数 `runtime` ("说明:")

## 函数信息
- **文件**: src/daemon/config/isulad_config.c
- **行号**: L292–L340
- **签名**: `char *conf_get_routine_rootdir(const char *runtime)`

## 污点源

| 参数 | 类型 | 污点来源 |
|------|------|----------|
| `runtime` (const char*) | 🔴 TAINTED | 外部配置输入，经调用链传入 |

## 数据流树状图

### INPUT-1: runtime (const char*) 🔴 TAINTED
├── [L297] `if (runtime == NULL)` → 条件判空，无污点传播
├── [L310] `strlen(runtime)` → 用于溢出边界检查 (`graph_len > SIZE_MAX - ... - strlen(runtime) - 3`)
│   └── 比较用，无污点传播
├── [L314] `strlen(runtime)` → 用于计算 `len = graph_len + 1 + strlen(ENGINE_ROOTPATH_NAME) + 1 + strlen(runtime) + 1`
│   └── `len` 🔴 TAINTED? 否 — 计算过程: graph_len(clean) + 常量 + strlen(runtime)(仅作长度值参与加法)
│       └── `len` 视为 **🟢 CLEANED**（仅取其数值，无污点内容传递）
├── [L325] `path = util_smart_calloc_s(sizeof(char), len)` → `path` 仅由 clean 参数分配 → 🟢 CLEANED buffer
└── [L324] `snprintf(path, len, "%s/%s/%s", conf->json_confs->graph, ENGINE_ROOTPATH_NAME, runtime)`
    → **`path` 🔴 TAINTED** — tainted `runtime` 被写入 `path`，生成新的污点载体
    └── [L340] `return path` → **📌 USED** (返回值携带污点)

## DIRECT SINK（高危操作）

| 位置 | 操作 | 风险说明 |
|------|------|----------|
| ⚠️ L324 | `snprintf(path, len, "%s/%s/%s", ..., runtime)` | `runtime` 拼接到文件系统路径中，攻击者可构造路径遍历序列（如 `../../etc`），可能导致目录穿越漏洞 |

## 污点终点汇总

| 脏数据 | 终点类型 | 位置 | 说明 |
|--------|---------|------|------|
| `path` (new tainted carrier) | 📌 USED | L340 | 函数返回值，`runtime` 拼接后的路径字符串返回给调用者 |

## 跟入子函数（叶函数）

本函数体内无任何子函数直接接收 `runtime` 或由其衍生的污点数据：
- `strlen(runtime)` — 标准库
- `snprintf(..., runtime)` — 标准库
- `util_smart_calloc_s(sizeof(char), len)` — 无污点参数传入
- `isulad_server_conf_rdlock()` — 无污点参数传入
- `conf_get_server_conf()` — 无污点参数传入

**结论**: 本函数为 **🟡 LEAF**（叶函数），污点通过返回值传递。