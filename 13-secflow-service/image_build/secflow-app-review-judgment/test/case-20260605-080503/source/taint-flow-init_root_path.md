# 数据流追踪: init_root_path

## 函数信息
- 文件: src/cmd/isulad-shim/process.c
- 行号: L1109-L1152
- 签名: `static int init_root_path(process_t *p)`

## 污点源识别

### 外部输入 (污点数据来源)

| ID | 参数 | 类型 | 来源 | 说明 |
|---|---|---|---|---|
| [INPUT-1] | p->workdir | char* | `getcwd(NULL,0)` → L1211 | 当前工作目录，攻击者可通过容器配置间接控制路径结构 |
| [INPUT-2] | p->state->runtime | char* | `shim_client_process_state_parse_file("process.json")` → L66 | **🔴 外部配置文件输入** — process.json 由 iSulad 守护进程生成，runtime 字段内容受守护进程控制，isulad-shim 无法验证其合法性 |
| [INPUT-3] | p->state->exec | bool | `shim_client_process_state_parse_file("process.json")` → L66 | process.json 中解析的 exec 标志 |

> **关键污点来源分析**: `process.json` 是由 iSulad 守护进程在 `/run/isulad/` 目录下生成的外部配置文件。isulad-shim 进程通过 `shim_client_process_state_parse_file()` 从该文件解析出 `runtime` 字段后直接使用，**没有任何白名单校验或路径规范化处理**。

---

## 逐行污点传播追踪

### INPUT-1: p->workdir (char*) 🔴 TAINTED

| 行号 | 代码 | 结果 | 说明 |
|---|---|---|---|
| L1113 | `state_path = isula_strdup_s(p->workdir);` | **state_path** 🔴 TAINTED | strdup 复制污点字符串，state_path 成为新的污点载体 |
| L1117 | `tmp_dir = strrchr(state_path, '/');` | state_path 🔴 TAINTED | strrchr 仅做指针查找，不改变污点状态 |
| L1124 | `tmp_dir = strrchr(state_path, '/');` | state_path 🔴 TAINTED | 第二次查找路径分隔符 |
| L1139 | `buffer->nappend(..., state_path, ...)` | buffer 内容 🔴 TAINTED | state_path 中的污点数据随 runtime 一起拼接入缓冲区 |

### INPUT-2: p->state->runtime (char*) 🔴 TAINTED — **核心危险输入**

| 行号 | 代码 | 结果 | 说明 |
|---|---|---|---|
| L1139 | `buffer->nappend(buffer, PATH_MAX, "%s/%s", state_path, p->state->runtime)` | buffer 内容 🔴 TAINTED | **⚠️ DIRECT_SINK**: 污点 runtime 字符串作为格式化参数写入缓冲区，无长度边界检查 |
| L1145 | `p->root_path = buffer->to_str(buffer)` | **p->root_path** 🔴 TAINTED [NEW CARRIER] | to_str() 将含污缓冲内容转为字符串，p->root_path 成为新的污点载体 |
| L1147 | `if (strlen(p->root_path) > PATH_MAX)` | p->root_path 🔴 TAINTED | 仅做长度检查，不清洗污点 |

### INPUT-3: p->state->exec (bool) 🔴 TAINTED

| 行号 | 代码 | 结果 | 说明 |
|---|---|---|---|
| L1115 | `if (p->state != NULL && p->state->exec)` | exec 用于条件判断 | 布尔值用于分支控制，未传播污点 |

---

## 数据流树状图

```
### INPUT-1: p->workdir (char*) 🔴 TAINTED [getcwd()]
├── [L1113] state_path = isula_strdup_s(p->workdir) → state_path 🔴 TAINTED [NEW CARRIER]
│   └── [L1117-1124] tmp_dir = strrchr(state_path, '/') (x2) → state_path 🔴 TAINTED
│       └── [L1139] buffer->nappend(..., state_path, p->state->runtime)
│           └── buffer 内容 🔴 TAINTED
└── [L1145] p->root_path = buffer->to_str(buffer) → p->root_path 🔴 TAINTED [NEW CARRIER]

### INPUT-2: p->state->runtime (char*) 🔴 TAINTED [process.json 外部文件输入]
├── [L1139] buffer->nappend(buffer, PATH_MAX, "%s/%s", state_path, p->state->runtime)
│   └── ⚠️ DIRECT_SINK: 污点 runtime 字符串直接作为格式化参数写入缓冲区
│       └── buffer 内容 🔴 TAINTED
└── [L1145] p->root_path = buffer->to_str(buffer) → p->root_path 🔴 TAINTED [NEW CARRIER]
```

---

## 污点终点汇总

| 脏数据 | 终点类型 | 位置 | 说明 |
|--------|----------|------|------|
| p->state->runtime | ⚠️ DIRECT_SINK | L1139 | 污点 runtime 作为格式化参数写入缓冲区，无长度验证 |
| p->root_path (新载体) | 结构体成员赋值 | L1145 | **关键终点**: p->root_path 成为新污点载体，被用于后续 CLI 参数 |
| p->root_path | strlen 长度验证 | L1147 | 长度检查，非终点 |
| p->root_path → params[] | 📌 USED | L1273 | **下游传播**: 作为 `--root` CLI 参数传递给 OCI runtime，可能导致路径注入 |

---

## 新导入污点载体追踪

| 新载体 | 来源 | 行号 | 后续传播 |
|--------|------|------|----------|
| **state_path** | isula_strdup_s(p->workdir) | L1113 | 路径字符串操作，拼接污点 runtime |
| **p->root_path** | buffer->to_str(buffer) | L1145 | → set_common_params() → params[] → execvp() → 间接命令注入风险 |

> ⚠️ **间接命令注入风险**: p->root_path 中的污点数据（包含攻击者可控的 runtime 字符串）通过 `--root` 命令行参数传递给 `execvp()` 执行的 OCI runtime。虽然通过 PATH_MAX 做了长度限制，但 runtime 字符串内容本身完全由 process.json 控制，且未经过路径规范化。

---

## 跟入表格 (Tainted Callee List)

> 以下函数调用接收了污点参数或由污点派生的新载体：

| 被调函数 | 位置 | 接收的污点参数 | 说明 |
|----------|------|----------------|------|
| `isula_strdup_s` | L1113 | p->workdir | 标准内存分配封装，仅复制数据，不记入 EXPORT |
| `isula_buffer.nappend` | L1139 | p->state->runtime, state_path | 🟡 **EXPORT** — isula_buffer 是 isula_libutils 外部库类，方法定义不在当前代码库中 |
| `isula_buffer.to_str` | L1145 | buffer | 🟡 **EXPORT** — 同上，返回值赋值给 p->root_path |
| `isula_buffer_free` | L1141 | buffer | 释放资源，无污点传播 |

```bash
bash gen_tainted_list <<'TAINTED_CALLEE_LIST'
src/cmd/isulad-shim/process.c###init_root_path###L1139###buffer,runtime,state_path
TAINTED_CALLEE_LIST
```