## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIBI_HandleOutputPktV4

## 函数信息
- 文件: libipsec.c
- 功能: 处理出站 IPv4 数据包的 IPSec 封装/处理入口函数
- 污点来源: mbuf (外部网络数据包缓冲区，outbound IPv4 packet)

---

## 污点源

| 变量 | 类型 | 说明 |
|------|------|------|
| `mbuf` | struct mbuf* | 🔴 TAINTED — 外部网络数据包缓冲区 (outbound IPv4 packet) |

---

## 新导入的污点对象 (在函数内产生)

| 变量 | 导入方式 | 位置 | 说明 |
|------|---------|------|------|
| `parse_state[]` | `IPSEC_PKT_ParseAndVerifyHdrV4()` 写入 | L11627 | IPv4 头部解析结果 |
| `control_info` | `MBUF_GetControlInfo(mbuf, 10)` 返回 | L11631 | mbuf 关联的控制元数据 |
| `send_if_index` | `MBUF_GetSendIfIndex(mbuf)` 返回 | L11608 | 发送接口索引 |
| `esp_spi` | `__builtin_bswap32(control_info[1])` | L11633 | ESP 安全参数索引 |
| `ah_spi` | `__builtin_bswap32(control_info[0])` | L11634 | AH 安全参数索引 |
| `dst_ipv4` | `__builtin_bswap32(RAW_U32(parse_state, PST_DST4_RAW))` | L11629 | 目的 IPv4 地址 |

---

## 完整数据流树状图

```
mbuf 🔴 TAINTED (外部网络数据包)
├── [L11608] send_if_index = MBUF_GetSendIfIndex(mbuf) → send_if_index 🔴 TAINTED
│   └── [L11609] RAW_U32(parse_state, PST_PKT_KIND) = send_if_index
│       └── parse_state[] 🔴 TAINTED (新导入)
│
├── [L11627] status = IPSEC_PKT_ParseAndVerifyHdrV4(mbuf, lib_ctx, parse_state, stats_ctx)
│   └── parse_state[] 🔴 TAINTED (新导入: output 参数)
│       ├── [L11629] dst_ipv4 = __builtin_bswap32(RAW_U32(parse_state, PST_DST4_RAW))
│       │   └── dst_ipv4 🔴 TAINTED (新导入)
│       └── [L11631] control_info = (uint32_t *)MBUF_GetControlInfo(mbuf, 10)
│           └── control_info 🔴 TAINTED (新导入)
│               ├── [L11633] esp_spi = __builtin_bswap32(control_info[1])
│               │   └── esp_spi 🔴 TAINTED (新导入)
│               ├── [L11634] ah_spi = __builtin_bswap32(control_info[0])
│               │   └── ah_spi 🔴 TAINTED (新导入)
│               └── [L11636] manual_sa = IPSEC_LIBI_GetManualSa(lib_ctx, parse_state, control_info)
│                   └── parse_state 🔴 TAINTED, control_info 🔴 TAINTED
│
├── [L11649] IPSEC_ESP_HandleOutputPktV4(lib_ctx, mbuf, parse_state, stats_ctx)
│   └── mbuf 🔴 TAINTED, parse_state[] 🔴 TAINTED
│
├── [L11690] IPSEC_AH_HandleOutputPktV4(lib_ctx, mbuf, parse_state, stats_ctx)
│   └── mbuf 🔴 TAINTED, parse_state[] 🔴 TAINTED
│
├── [L11723] MBUF_ClearFlag(mbuf, 0x10000000) — flag 操作
├── [L11724] MBUF_SetFlag(mbuf, 0x4000) — flag 操作
├── [L11725] MBUF_SetFlag(mbuf, 0x20000000) — flag 操作
├── [L11726] MBUF_DeleteControlInfo(mbuf, 10) — 删除元数据
│
├── [L11754] fallback: IPSEC_ESP_HandleOutputPktV4(...)
│   └── mbuf 🔴 TAINTED
│
└── [L11775] fallback: IPSEC_PKT_ParseAndVerifyHdrV4(mbuf, ...)
    └── mbuf 🔴 TAINTED
```

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf | 📌 USED | L11649, L11690 | 传递给 ESP/AH 输出处理函数 |
| parse_state[] | 📌 USED | L11649, L11690 | 传递 IPv4 头部解析结果 |
| control_info | ⚠️ DIRECT_SINK | L11631 | 从 mbuf 提取 SPI/端口控制信息 |
| esp_spi | ⚠️ DIRECT_SINK | L11633 | 从被污染的控制数据提取 32-bit ESP SPI |
| ah_spi | ⚠️ DIRECT_SINK | L11634 | 从被污染的控制数据提取 32-bit AH SPI |
| dst_ipv4 | ⚠️ DIRECT_SINK | L11629 | 从被污染的 mbuf 解析数据提取目的地址 |

---

## 直接 Sink 标注

| 行号 | 操作 | 风险描述 |
|------|------|----------|
| L11631 | MBUF_GetControlInfo(mbuf, 10) | CRITICAL: 从 mbuf 提取 SPI/端口控制信息，决定加密/认证算法选择 |
| L11633 | esp_spi = __builtin_bswap32(control_info[1]) | 从被污染的 mbuf 控制数据中提取 32-bit ESP SPI |
| L11634 | ah_spi = __builtin_bswap32(control_info[0]) | 从被污染的 mbuf 控制数据中提取 32-bit AH SPI |
| L11636 | IPSEC_LIBI_GetManualSa(..., parse_state, control_info) | SA 查找使用源自 mbuf 的被污染头部字段和控制信息 |