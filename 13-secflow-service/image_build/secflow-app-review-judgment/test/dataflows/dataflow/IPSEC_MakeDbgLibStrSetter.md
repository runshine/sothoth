## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `esp_spi` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_MakeDbgLibStrSetter

## 函数信息
- 文件: libipsec.c
- 行号: L21496 (函数入口)
- 签名: `int64_t IPSEC_MakeDbgLibStrSetter(int64_t lib_ctx, int comp_id, int line_no, const char *fmt, ...)`

## 数据流树状图

### INPUT-1: esp_spi (uint32_t) 🔴 TAINTED
├── [L21496] 函数入口 — esp_spi 作为 variadic 参数接收
│   来源: control_info[1] ← MBUF_GetControlInfo() — 外部网络输入
│   调用点: L11661 调用 IPSEC_MakeDbgLibStrSetter(..., esp_spi, ah_spi)
│
├── [L21512] va_start(ap, fmt)
│   └── esp_spi 🔴 TAINTED — 进入 variadic 参数列表
│
└── [L21513] vsnprintf_truncated_s(out_str + prefix_len, 513 - prefix_len, fmt, ap)
    │   esp_spi 作为 variadic 实参传入 ap
    │   格式字符串为 "ESP-SPI is %d, AH-SPI is %d" (字面量，安全)
    │   esp_spi 按 %d 格式化 → 十进制整数 (安全转换)
    │
    └── [L21514] va_end(ap)
        └── 📌 USED — 格式化结果写入 out_str (lib_ctx + 448)
            └── 后续调用 SSP_Debug(..., "%s", lib_ctx + 448) 用于调试输出

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| esp_spi | 📌 USED | L21513 | 作为 variadic 参数传递给 vsnprintf_truncated_s，最终格式化到调试字符串 |

## 新引入的污点对象
无 — 函数内无输出参数写入操作，所有操作均为对本函数参数的直接处理。

## 安全说明
- 格式字符串 `fmt` 为硬编码字面量 `"ESP-SPI is %d, AH-SPI is %d"`，攻击者无法控制
- `esp_spi` 按 `%d` 格式化，无指针解释风险