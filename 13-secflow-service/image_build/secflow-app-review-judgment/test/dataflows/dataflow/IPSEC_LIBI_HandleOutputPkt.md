## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIBI_HandleOutputPkt

## 函数信息
- 文件: libipsec.c
- 签名: `int IPSEC_LIBI_HandleOutputPkt(libipsec_ctx_t *lib_ctx, struct mbuf *mbuf, ...)`

## 污点源

### INPUT-1: mbuf (struct mbuf*) 🔴 TAINTED
外部网络输入的网络包缓冲区。

| 行号 | 操作 | 结果 | 说明 |
|------|------|------|------|
| L10804 | null check | 无传播 | 仅做空指针检查 |
| L10807 | MBUF_GetSendIfIndex(mbuf) | 🟢 CLEANED | 提取接口索引标量，不含包载荷 |
| L10825 | IPSEC_PKT_ParseAndVerifyHdr(mbuf, lib_ctx, &parse_state) | ⚠️ NEW_OBJECT | 输出参数 `parse_state` 被写入 |
| L10852 | MBUF_GetControlInfo(mbuf, 10) | 🟢 CLEANED | 提取元数据，非包载荷 |
| L10861 | IPSEC_AH_HandleOutputPkt(lib_ctx, mbuf, parse_state) | 📎 子函数 | mbuf 作为参数传入 |
| L10890 | IPSEC_ESP_HandleOutputPkt(lib_ctx, mbuf, parse_state) | 📎 子函数 | mbuf 作为参数传入 |
| L10911-L10913 | MBUF_ClearFlag/SetFlag/DeleteControlInfo(mbuf) | ⚠️ 终态 | mbuf 状态操作终态 |

## 新引入的污点对象

### parse_state (输出参数) 🔴 TAINTED
- **引入方式**: `IPSEC_PKT_ParseAndVerifyHdr(mbuf, lib_ctx, &parse_state)` 在 L10825 写入
- **污点来源**: mbuf 网络包头中的字段解析
- **字段映射**:
  - `parse_state[12..15]` (PST_SPI) ← mbuf 头部的 SPI 字段
  - `parse_state[36..51]` (PST_DST6) ← mbuf 目标地址字段

| 行号 | 操作 | 结果 | 说明 |
|------|------|------|------|
| L10861 | IPSEC_AH_HandleOutputPkt(lib_ctx, mbuf, parse_state) | 📎 子函数 | parse_state 作为参数传入 |
| L10890 | IPSEC_ESP_HandleOutputPkt(lib_ctx, mbuf, parse_state) | 📎 子函数 | parse_state 作为参数传入 |

## 数据流树状图

```
### INPUT-1: mbuf (struct mbuf*) 🔴 TAINTED
├── [L10804] null check → 无传播
├── [L10807] MBUF_GetSendIfIndex(mbuf) → send_if_index 🟢 CLEANED
├── [L10825] IPSEC_PKT_ParseAndVerifyHdr(mbuf, lib_ctx, &parse_state)
│   └── parse_state 🔴 TAINTED ⚠️ NEW_OBJECT
│       ├── [L10861] IPSEC_AH_HandleOutputPkt(lib_ctx, mbuf, parse_state) → 📎 子函数
│       └── [L10890] IPSEC_ESP_HandleOutputPkt(lib_ctx, mbuf, parse_state) → 📎 子函数
├── [L10861] IPSEC_AH_HandleOutputPkt(lib_ctx, mbuf, parse_state) → 📎 子函数
├── [L10890] IPSEC_ESP_HandleOutputPkt(lib_ctx, mbuf, parse_state) → 📎 子函数
└── [L10911-L10913] MBUF_* operations → ⚠️ 终态

### NEW_OBJECT: parse_state 🔴 TAINTED
├── [L10861] IPSEC_AH_HandleOutputPkt(lib_ctx, mbuf, parse_state)
└── [L10890] IPSEC_ESP_HandleOutputPkt(lib_ctx, mbuf, parse_state)
```

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf | IPSEC_PKT_ParseAndVerifyHdr | L10825 | mbuf 作为入参，解析头字段 |
| mbuf | IPSEC_AH_HandleOutputPkt | L10861 | mbuf 作为入参 |
| mbuf | IPSEC_ESP_HandleOutputPkt | L10890 | mbuf 作为入参 |
| mbuf | MBUF_* operations | L10911-L10913 | mbuf 状态操作终态 |
| parse_state | IPSEC_AH_HandleOutputPkt | L10861 | parse_state 作为入参 |
| parse_state | IPSEC_ESP_HandleOutputPkt | L10890 | parse_state 作为入参 |