# 数据流追踪: isulad_set_error_message — 参数 `说明:`

## 函数信息
- **文件**: src/daemon/common/err_msg.c
- **行号**: L28-L49
- **签名**: `void isulad_set_error_message(const char *format, ...)`

## 数据流树状图

### INPUT-1: format (const char*) 🔴 TAINTED — 外部格式化字符串输入
```
├── [L32] if (format == NULL) { return; } → format 未修改，仅做 NULL 保护检查
├── [L34] va_start(argp, format) → argp 🔴 TAINTED
└── [L36] ret = vsnprintf(errbuf, BUFSIZ, format, argp)
    ├── ⚠️ DIRECT_SINK: 污点 format 作为格式化字符串，可含 %n 等危险占位符导致越界写
    └── [L36] errbuf 🔴 TAINTED (新导入的 tainted carrier)
        └── [L43] g_isulad_errmsg = util_strdup_s(errbuf) → 📌 USED (全局错误消息被污染)
```

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| format | ⚠️ DIRECT_SINK: vsnprintf format string | L36 | 污点数据作为格式化字符串，可含恶意 `%n` 等规格符 |
| errbuf | 📌 USED: g_isulad_errmsg | L43 | 新导入 tainted carrier，util_strdup_s 写入全局变量 |

## 关键发现
1. **⚠️ DIRECT_SINK (L36)**: `vsnprintf(errbuf, BUFSIZ, format, argp)` — `format` 参数由污点数据控制，若调用者传入含 `%n`、`%999999x` 等恶意格式化占位符，可触发越界写入或其他内存破坏。
2. **`errbuf` 晋升为新 tainted carrier (L36)**: vsnprintf 的输出缓冲区在调用后承载了格式化后的结果，需继续追踪。
3. **全局传播终点 (L43)**: `g_isulad_errmsg = util_strdup_s(errbuf)` — 全局 `__thread` 变量 `g_isulad_errmsg` 接收了被污染的 `errbuf`，后续任何读取该全局变量的代码均受到污染影响。
4. 此函数作为公共错误消息接口，所有调用方的污点数据均可通过此接口注入全局状态。

## 跟入表格（子函数）
- 无子函数直接接收污点参数 `format`（`vsnprintf`、`util_strdup_s` 为标准库函数，标记 🟡 EXPORT）

---

*本报告仅追踪数据流，不做漏洞评估。*