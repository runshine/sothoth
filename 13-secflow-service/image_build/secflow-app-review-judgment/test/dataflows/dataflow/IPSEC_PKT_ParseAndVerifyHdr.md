## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_PKT_ParseAndVerifyHdr

## 函数信息
- 文件: `libipsec.c`
- 签名: `int IPSEC_PKT_ParseAndVerifyHdr(...)`
- 污点输入: `mbuf` — 外部网络数据包缓冲区

---

## 污点源

| 参数 | 类型 | 状态 | 说明 |
|------|------|------|------|
| `mbuf` | (mbuf*) | 🔴 TAINTED | 外部网络数据包缓冲区，由调用者传入 |

---

## 新导入的污点对象

| 对象 | 类型 | 状态 | 导入方式 | 位置 |
|------|------|------|----------|------|
| `ip_header` | uint8_t* | 🔴 TAINTED | `MBUF_MakeMemoryContinuous_fl(mbuf, 0, 40, ...)` 输出指针 | L10415 |
| `ext_header` | uint8_t* | 🔴 TAINTED | `MBUF_MakeMemoryContinuous_fl(mbuf, offset, len, ...)` 输出指针 | L10490/L10567/L10695/L10712 |
| `ah_header` | uint8_t* | 🔴 TAINTED | `MBUF_MakeMemoryContinuous_fl(mbuf, offset, len, ...)` 输出指针 | L10520 |
| `esp_header` | uint8_t* | 🔴 TAINTED | `MBUF_MakeMemoryContinuous_fl(mbuf, offset, len, ...)` 输出指针 | L10540 |
| `offset` | uint16_t | 🔴 TAINTED | 由污点 `ext_header[1]` 驱动增长 | L10572/L10705/L10720 |
| `next_header` | uint8_t | 🔴 TAINTED | 由 `ext_header[0]` 提取 | 多处 |
| `total_packet_len` | uint16_t | 🔴 TAINTED | 由污点 `packet_len_field` 计算 | L10445 |
| `state[PST_SPI]` | uint32_t | 🔴 TAINTED | 由污点 SPI 数据写入输出参数 | L10527/L10546 |
| `state[PST_HDR_OFFSET]` | uint16_t | 🔴 TAINTED | 由污点偏移写入输出参数 | L10526 |
| `state[PST_PACKET_LEN]` | uint16_t | 🔴 TAINTED | 由污点长度字段写入输出参数 | L10442 |
| `state[PST_TOTAL_LEN]` | uint32_t | 🔴 TAINTED | 由污点 total_data_len 写入输出参数 | L10444 |

---

## 传播路径图

```
mbuf 🔴 TAINTED (外部网络输入)
└── L10415: MBUF_MakeMemoryContinuous_fl(mbuf, 0, 40, ...)
    └── ip_header 🔴 TAINTED (新污点载体)
        ├── L10435: RAW_U8(ip_header, 0) → version_nibble 🔴 TAINTED
        ├── L10442: RAW_U16(ip_header, 4) → state[PST_PACKET_LEN] 🔴 TAINTED
        │   └── state[PST_PACKET_LEN] → 📌 USED (写入state数组)
        ├── L10444: state[PST_TOTAL_LEN] = (uint32_t)total_data_len 🔴 TAINTED
        │   └── state[PST_TOTAL_LEN] → 📌 USED (写入state数组)
        ├── L10444–L10445: packet_len_field + 40 → total_packet_len 🔴 TAINTED
        │   └── total_packet_len → 📌 USED (长度计算)
        ├── L10460: RAW_U8(ip_header, 6) → next_header 🔴 TAINTED
        │   └── next_header → 📌 USED (扩展头类型判断)
        └── while(1) 循环 — IPv6 扩展头链解析
            ├── [路由44 Fragment]
            │   └── L10490: MBUF_MakeMemoryContinuous_fl(mbuf, offset, 8, ...)
            │       └── ext_header 🔴 TAINTED
            │           ├── ext_header[0] → next_header 🔴 TAINTED
            │           └── offset += 8 (固定步长)
            │
            ├── [路由51 AH]
            │   └── L10520: MBUF_MakeMemoryContinuous_fl(mbuf, offset, total_len-offset, ...)
            │       └── ah_header 🔴 TAINTED
            │           ├── L10526: state[PST_HDR_OFFSET] = offset → 📌 USED
            │           └── L10527: state[PST_SPI] = bswap32(ah_header[4]) → 📌 USED
            │
            ├── [路由50 ESP]
            │   └── L10540: MBUF_MakeMemoryContinuous_fl(mbuf, offset, total_len-offset, ...)
            │       └── esp_header 🔴 TAINTED
            │           └── L10546: state[PST_SPI] = bswap32(*esp_header) → 📌 USED
            │
            ├── [路由60 Destination-Option]
            │   └── L10567: MBUF_MakeMemoryContinuous_fl(mbuf, offset, 2, ...)
            │       └── ext_header 🔴 TAINTED
            │           ├── ext_header[0] → next_header 🔴 TAINTED
            │           └── L10572: ⚠️ DIRECT_SINK: offset += 8*(ext_header[1]+1)
            │               └── 步长由污点 ext_header[1] 控制
            │
            ├── [路由0 Hop-by-Hop]
            │   └── L10695: MBUF_MakeMemoryContinuous_fl(mbuf, offset, 2, ...)
            │       └── ext_header 🔴 TAINTED
            │           ├── ext_header[0] → next_header 🔴 TAINTED
            │           └── L10705: ⚠️ DIRECT_SINK: offset += 8*(ext_header[1]+1)
            │               └── 步长由污点控制
            │
            └── [路由43 Routing]
                └── L10712: MBUF_MakeMemoryContinuous_fl(mbuf, offset, 4, ...)
                    └── ext_header 🔴 TAINTED
                        ├── ext_header[0] → next_header 🔴 TAINTED
                        └── L10720: ⚠️ DIRECT_SINK: offset += 8*(ext_header[1]+1)
                            └── 步长由污点控制
```

---

## 高危 Sink 汇总

| 污点字段 | 位置 | 风险描述 |
|----------|------|----------|
| `ext_header[1]` | L10572 | ⚠️ DIRECT_SINK: IPv6 扩展头长度字段，可导致指针越界 |
| `ext_header[1]` | L10705 | ⚠️ DIRECT_SINK: IPv6 扩展头长度字段，可导致指针越界 |
| `ext_header[1]` | L10720 | ⚠️ DIRECT_SINK: IPv6 扩展头长度字段，可导致指针越界 |
| `offset` | 循环条件 | ⚠️ DIRECT_SINK: 偏移量由污点数据驱动，可能导致缓冲区越界读取 |
| `total_len - offset` | L10520/L10540 | ⚠️ DIRECT_SINK: 读取大小由污点偏移控制，可导致越界读取 |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `state[PST_PACKET_LEN]` | 写入 state 数组 | L10442 | IP 包长度存储 |
| `state[PST_TOTAL_LEN]` | 写入 state 数组 | L10444 | 总长度存储 |
| `state[PST_HDR_OFFSET]` | 写入 state 数组 | L10526 | AH 头偏移存储 |
| `state[PST_SPI]` | 写入 state 数组 | L10527/L10546 | SPI 值存储 |
| `offset` | MBUF_MakeMemoryContinuous_fl 参数 | L10490等 | 控制后续读取位置 |