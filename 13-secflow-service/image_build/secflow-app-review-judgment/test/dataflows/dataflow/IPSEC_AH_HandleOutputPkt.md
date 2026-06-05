## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_AH_HandleOutputPkt

## 函数信息
- 文件: libipsec.c
- 函数: IPSEC_AH_HandleOutputPkt
- 输入参数: mbuf, parse_state (unsigned int*)

---

## INPUT-1: mbuf (mbuf*) 🔴 TAINTED
> 外部输入网络数据包缓冲区

### 传播路径

```
[L5238] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf, 0, packet_info[0], ...)
    └── ip_header 🔴 TAINTED
        ├── [L5261] IPSEC_LIB_Ipv6AddrToStr(ip_header+8, src_addr_str, 65) → 提取源地址
        ├── [L5262] IPSEC_LIB_Ipv6AddrToStr(ip_header+24, dst_addr_str, 65) → 提取目的地址
        ├── [L5330] RAW_U8(ip_header, packet_info[1]) = 51 → 修改协议字段
        └── [L5332] RAW_U16(ip_header, 4) = ... → 修改 IP 长度

[L5348] chunk_base = MBUF_MakeMemoryContinuous_fl(mbuf, read_offset, copy_len, ...)
    └── chunk_base 🔴 TAINTED
        ├── [L5373] memcpy_s(payload_cursor, chunk_size, chunk_base, chunk_size)
        │   └── payload_copy 🔴 TAINTED（memcpy 目的端新载体）
        └── [L5407] 循环重复调用，返回 chunk_base

[L5405] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, packet_info[0], &header_copy)
    └── header_copy 🔴 TAINTED（输出参数导入）
        ├── [L5408] saved_word0 = RAW_U32(header_copy, 0) → 保存原始字段
        ├── [L5411] RAW_U32(header_copy, 0) = 0 → 清零操作
        ├── [L5447] RAW_U32(header_copy, 0) = saved_word0 → 恢复
        └── [L5471] MBUF_CopyDataFromBufferToMBuf(mbuf, ..., header_copy, ...)

[L5448] MBUF_PrependMemorySpace_fl(mbuf, ...) → mbuf 空间扩展
[L5455] MBUF_MakeMemoryContinuous_fl(mbuf, ...) → 重新获取 mbuf 指针
```

### 新导入的污点载体
| 对象 | 导入方式 | 行号 |
|------|----------|------|
| ip_header | MBUF_MakeMemoryContinuous_fl 返回数据指针 | L5238 |
| chunk_base | MBUF_MakeMemoryContinuous_fl 返回分块指针 | L5348, L5407 |
| header_copy | MBUF_CopyDataFromMBufToBuffer 输出参数 | L5405 |
| payload_copy | memcpy_s 目的端（chunk_base 污点传播） | L5373 |

---

## INPUT-2: parse_state (unsigned int*) 🔴 TAINTED
> 外部网络输入，作为 packet_info 数组使用

### 传播路径

```
packet_info[0] (IP头长度)
├── [L5248] → MBUF_MakeMemoryContinuous_fl 大小参数 → ip_header 🔴 TAINTED
│   ├── [L5323] RAW_U8((void *)ip_header, packet_info[1]) = 51 ⚠️ DIRECT_SINK: 污点索引写入
│   └── [L5328] RAW_U16((void *)ip_header, 4) = __builtin_bswap16(...)
├── [L5361] → MBUF_MakeMemoryContinuous_fl 偏移参数: read_offset
├── [L5381] → VRP_Malloc_F 分配大小 → header_copy 🔴 TAINTED
│   ├── [L5467] MBUF_CopyDataFromMBufToBuffer(..., packet_info[0], header_copy)
│   ├── [L5489] algo_desc[7](auth_ctx, header_copy, packet_info[0])
│   └── [L5526] MBUF_CopyDataFromBufferToMBuf(..., packet_info[0], header_copy, ...)
└── [L5549] → MBUF_CopyDataFromBufferToMBuf 偏移

packet_info[1] (下一头部类型)
├── [L5318-5319] → 条件分支判断
└── [L5323] RAW_U8((void *)ip_header, packet_info[1]) = 51 ⚠️ DIRECT_SINK: 污点索引写入

packet_info[3] (SA索引)
├── [L5267] → sa_lookup_key 🔴 TAINTED
│   └── [L5269] sa_entry = VOS_AVL3_Find(..., &sa_lookup_key, ...) → sa_entry 🔴 TAINTED
└── [L5427] → RAW_U32(auth_header, 4) → auth_header 🔴 TAINTED

packet_info[4] (负载长度)
├── [L5302-5303] → payload_len 🔴 TAINTED
│   └── payload_offset = payload_len - packet_info[0] → payload_offset 🔴 TAINTED
│       ├── [L5340] VRP_Malloc_F(..., payload_offset, ...) → payload_copy 🔴 TAINTED ⚠️ DIRECT_SINK: 分配大小受污点控制
│       └── [L5337-5389] 循环复制 payload_copy，使用 payload_offset 控制循环
└── [L5506] auth_hash_len + 12 + *((uint16_t *)packet_info + 5) 用于大小计算

packet_info[9-12] → selector_words[0-3] 🔴 TAINTED
├── [L5300] IPSECL_DBG_AhPktAlgo(..., selector_words[0], selector_words[1], &algo_dbg_word)
└── [L5463] IPSECL_DBG_AhPktAlgo(...)

packet_info[14] → algo_dbg_word 🔴 TAINTED

packet_info[32] → auth_header[0] 🔴 TAINTED
├── [L5423] *((uint8_t *)packet_info + 32) → auth_header[0]
└── [L5542] MBUF_CopyDataFromBufferToMBuf(..., packet_info[0], ..., auth_header, ...)

*((uint16_t *)packet_info + 5) → ip_header 字段写入
```

### 新导入的污点载体
| 对象 | 导入方式 | 行号 |
|------|----------|------|
| ip_header | MBUF_MakeMemoryContinuous_fl (packet_info[0] 作为大小参数) | L5248 |
| sa_entry | VOS_AVL3_Find (sa_lookup_key ← packet_info[3]) | L5269 |
| payload_copy | VRP_Malloc_F (payload_offset ← packet_info[4]-packet_info[0]) | L5340 |
| header_copy | VRP_Malloc_F (packet_info[0] 作为分配大小) | L5381 |
| auth_header | 从 packet_info 字段写入 | L5423, L5427 |
| selector_words | packet_info[9-12] → selector_words[0-3] | L5240-5243 |
| algo_dbg_word | packet_info[14] | L5297 |

---

## 污点终点汇总

### 📌 数据消费（读取污点数据）
| 位置 | 操作 | 说明 |
|------|------|------|
| L5261 | IPSEC_LIB_Ipv6AddrToStr(ip_header+8, ...) | 提取 IPv6 源地址 |
| L5262 | IPSEC_LIB_Ipv6AddrToStr(ip_header+24, ...) | 提取 IPv6 目的地址 |
| L5300 | IPSECL_DBG_AhPktAlgo(..., selector_words[0], ...) | 调试日志 |
| L5463 | IPSECL_DBG_AhPktAlgo(..., selector_words[0], ...) | 调试日志 |

### ⚠️ DIRECT_SINK（高危操作）
| 位置 | 操作 | 风险类型 |
|------|------|----------|
| L5248 | MBUF_MakeMemoryContinuous_fl(..., packet_info[0], ...) | 分配大小受污点控制 |
| L5323 | RAW_U8((void *)ip_header, packet_info[1]) = 51 | 污点索引写入，越界风险 |
| L5340 | VRP_Malloc_F(..., payload_offset, ...) | 分配大小受污点控制 |
| L5348 | MBUF_MakeMemoryContinuous_fl(..., read_offset, ...) | 偏移受污点控制 |
| L5373 | memcpy_s(payload_cursor, chunk_size, chunk_base, chunk_size) | 污点指针/长度 |
| L5381 | VRP_Malloc_F(..., packet_info[0], ...) | 分配大小受污点控制 |
| L5405 | MBUF_CopyDataFromMBufToBuffer(..., packet_info[0], header_copy) | 复制大小受污点控制 |
| L5467 | MBUF_CopyDataFromMBufToBuffer(..., packet_info[0], header_copy) | 复制大小受污点控制 |
| L5489 | algo_desc[7](auth_ctx, header_copy, packet_info[0]) | 长度参数受污点控制 |
| L5516 | MBUF_MakeMemoryContinuous_fl(..., auth_hash_len+12+packet_info[0], ...) | 总大小计算受污点影响 |
| L5526 | MBUF_CopyDataFromBufferToMBuf(..., packet_info[0], header_copy, ...) | 复制大小受污点控制 |
| L5542 | MBUF_CopyDataFromBufferToMBuf(..., packet_info[0], ..., auth_header, ...) | 偏移受污点控制，越界写入风险 |
| L5549 | MBUF_CopyDataFromBufferToMBuf 偏移 | 偏移受污点控制 |

---

## 新导入污点载体的下游传播

### header_copy 🔴 TAINTED
```
└── [L5405] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, packet_info[0], &header_copy)
    ├── [L5408] RAW_U32(header_copy, 0) → 提取字段值
    ├── [L5411] RAW_U32(header_copy, 0) = 0 → 修改字段
    ├── [L5447] RAW_U32(header_copy, 0) = saved_word0 → 恢复字段
    ├── [L5467] MBUF_CopyDataFromMBufToBuffer(..., packet_info[0], header_copy) ⚠️ 复制大小受污点
    ├── [L5489] algo_desc[7](auth_ctx, header_copy, packet_info[0]) ⚠️ 长度参数受污点
    ├── [L5526] MBUF_CopyDataFromBufferToMBuf(..., packet_info[0], header_copy, ...) ⚠️ 复制大小受污点
    └── [L5471] MBUF_CopyDataFromBufferToMBuf(mbuf, ..., header_copy, ...) → 写回 mbuf
```

### payload_copy 🔴 TAINTED
```
└── [L5340] VRP_Malloc_F(..., payload_offset, ...)
    └── [L5337-5389] 循环复制 payload_copy（payload_offset 控制循环次数）
        └── [L5373] memcpy_s(payload_cursor, chunk_size, chunk_base, chunk_size) ⚠️ DIRECT_SINK
```

### auth_header 🔴 TAINTED
```
└── [L5423] *((uint8_t *)packet_info + 32) → auth_header[0]
└── [L5427] RAW_U32(auth_header, 4) = packet_info[3]
    └── [L5542] MBUF_CopyDataFromBufferToMBuf(..., packet_info[0], ..., auth_header, ...) ⚠️ 偏移受污点
```

### sa_entry 🔴 TAINTED
```
└── [L5269] sa_entry = VOS_AVL3_Find(..., &sa_lookup_key, ...)
    └── 用于后续 SA 相关操作
```