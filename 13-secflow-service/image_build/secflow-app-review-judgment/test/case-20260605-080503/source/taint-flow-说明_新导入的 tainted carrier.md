# 数据流追踪: 说明: (在函数 openlog 中)

## 函数信息
- 文件: `src/cmd/isulad-shim/terminal.c`
- 行号: L435
- 签名: `void openlog(const char *ident, int option, int facility)` （标准 C 库函数）

## ⚠️ 函数位置声明

> **函数 `openlog` 不存在于 `src/daemon/modules/spec/specs.c`（任务描述指向的文件）。**
> 该函数是标准 C 库函数（定义于 `<syslog.h>`），实际源码位于：
> `src/cmd/isulad-shim/terminal.c` 的包装函数 `shim_init_syslog` 中调用。

---

## 污点源

| 编号 | 参数 | 类型 | 污点状态 | 来源 |
|------|------|------|----------|------|
| INPUT-1 | `name` (const char*) | 🔴 TAINTED | **外部输入** — 容器 ID/名称，来自容器创建请求或命令行参数 |
| INPUT-2 | `tag` (const char*) | 🔴 TAINTED | **外部输入** — `p_state->syslog_tag`，来自进程状态配置 |

---

## 当前函数内传播路径

### INPUT-1: name (const char*) 🔴 TAINTED — 容器标识符

```
shim_init_syslog(name, tag, facility)
└── [L423] if (tag != NULL) → 条件分支，tag 为 NULL 时执行 else
    └── [L423] syslog_tag = isula_sub_string(name, 0, SHORT_ID_LEN)
        └── [L435] openlog(syslog_tag, LOG_PID, facility_num)
            └── ⚠️ DIRECT_SINK: syslog_tag 作为 ident 参数直接写入系统日志
```

### INPUT-2: tag (const char*) 🔴 TAINTED — 显式日志标签

```
shim_init_syslog(name, tag, facility)
└── [L416-417] if (tag != NULL) → 非 NULL 时执行
    └── [L417] syslog_tag = tag
        └── [L435] openlog(syslog_tag, LOG_PID, facility_num)
            └── ⚠️ DIRECT_SINK: syslog_tag 作为 ident 参数直接写入系统日志
```

### NEW CARRIER: syslog_tag (const char*) 🔴 TAINTED

```
[L417/423] syslog_tag = (tag != NULL) ? tag : isula_sub_string(name, 0, SHORT_ID_LEN)
    └── [L435] openlog(syslog_tag, LOG_PID, facility_num)
        └── ⚠️ DIRECT_SINK: 污点 ident 字符串作为 syslog 标识符
        └── 📌 USED: 作为 openlog 的 ident 参数，记录到系统日志
```

---

## 高危操作汇总

| 位置 | 操作 | 风险描述 |
|------|------|----------|
| L435 | `openlog(syslog_tag, LOG_PID, facility_num)` | **⚠️ 污点 ident 写入系统日志**：syslog_tag 来自外部输入的容器名或显式标签，未经任何消毒处理即作为日志标识符。若内容包含特殊字符（如换行符），可能被用于日志注入攻击。 |
| L423 | `isula_sub_string(name, 0, SHORT_ID_LEN)` | 截断操作不影响污点状态，只限制长度。name 的前 15 字符仍为脏数据。 |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `name` | `openlog(ident)` | L435 | 容器标识符（外部输入）作为 syslog 标识符 |
| `tag` | `openlog(ident)` | L435 | 显式标签（外部输入）作为 syslog 标识符 |
| `syslog_tag` | 系统日志 | L435 | 污点字符串直接写入系统日志，可能导致日志伪造或注入 |

---

## 调用链追溯

```
shim_init_syslog(id, p_state->syslog_tag, p_state->syslog_facility)
  ↑ 调用点：process.c:1006
  ↑ p_state 来自容器配置（外部输入）
```

**上游污点链**：
- `id` = 容器 ID → 来自容器创建请求/命令行 → 🔴 TAINTED
- `p_state->syslog_tag` → 来自进程状态配置 → 🔴 TAINTED

---

*本报告仅追踪数据流，不做漏洞评估。*