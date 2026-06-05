## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_AH_HandleOutputPktV4

## 函数信息
- 文件: libipsec.c
- 函数签名: `int IPSEC_AH_HandleOutputPktV4(void* mbuf_base, unsigned int* parse_state)`

## 外部输入参数(已污染)
| 参数 | 类型 | 来源 |
|------|------|------|
| `mbuf_base` | `void*` | 外部网络数据包缓冲区 |
| `parse_state` | `unsigned int*` | 调用者通过 `IPSEC_PKT_ParseAndVerifyHdrV4()` 从 IPv4 网络包解析得到的 64 字节缓冲区 (packet_info) |

---

## 数据流树状图

### INPUT-1: mbuf_base (void*) 🔴 TAINTED
```
├── [L6188] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf_base, 0, packet_info[0], ...)
│   └── ip_header 🔴 TAINTED
│       ├── [L6195] IPSEC_LIB_Ipv4AddrToStr(ip_header+12, ...) → src_addr_text 🟢 CLEANED (仅格式化)
│       ├── [L6196] IPSEC_LIB_Ipv4AddrToStr(ip_header+16, ...) → dst_addr_text 🟢 CLEANED (仅格式化)
│       ├── [L6208] RAW_U8(ip_header, 9) = 51 → mbuf 被修改
│       └── [L6209] RAW_U16(ip_header, 2) = ... → mbuf 被修改
│
├── [L6229] LOOP: chunk_base = MBUF_MakeMemoryContinuous_fl(mbuf_base, read_offset, chunk_len, ...)
│   └── chunk_base 🔴 TAINTED
│       └── [L6235] memcpy_s(payload_cursor, chunk_len, chunk_base, chunk_len)
│           ⚠️ DIRECT_SINK: chunk_base(污点指针) + chunk_len(污点大小) 控制拷贝
│           └── payload_copy 🔴 TAINTED (新污点对象)
│               ├── [L6518] algo_desc[7](auth_ctx, payload_copy, payload_offset)
│               └── [L6527] algo_desc[7](auth_ctx, payload_copy, payload_offset)
│
├── [L6467] MBUF_CopyDataFromMBufToBuffer(mbuf_base, 0, packet_info[0], header_copy)
│   └── header_copy 🔴 TAINTED (新污点对象)
│       ├── [L6476] saved_tos = header_copy[1]
│       ├── [L6477] saved_id = *(uint16_t*)(header_copy+4)
│       ├── [L6478] saved_frag_off = *(uint16_t*)(header_copy+6)
│       ├── [L6479] saved_ttl = header_copy[8]
│       ├── [L6498] chunk_len = header_copy[option_offset + 1]
│       │   ⚠️ DIRECT_SINK: 选项长度字段来自污点数据，控制解析进度
│       ├── [L6502] algo_desc[7](auth_ctx, header_copy + option_offset, chunk_len)
│       ├── [L6508] header_len = 4u * (header_copy[0] & 0xF)
│       │   ⚠️ DIRECT_SINK: 头部长度字段来自污点数据，控制循环边界
│       ├── [L6519] ip_header = MBUF_MakeMemoryContinuous_fl(...) → ip_header 🔴 TAINTED 刷新
│       ├── [L6529] MBUF_CopyDataFromBufferToMBuf(mbuf_base, 0, packet_info[0], header_copy, ...)
│       │   ⚠️ DIRECT_SINK: 污点 header_copy 写回 mbuf
│       └── [L6534] memcpy_s(auth_header+12, auth_hash_len, auth_value, auth_hash_len)
│
├── [L6513] MBUF_PrependMemorySpace_fl(mbuf_base, auth_hash_len + 12, ...)
│   └── mbuf 被重新分配
│
└── [L6547] MBUF_CopyDataFromBufferToMBuf(mbuf_base, packet_info[0], auth_hash_len+12, auth_header, ...)
    ⚠️ DIRECT_SINK: auth_header(含mbuf来源数据) 写入 mbuf 偏移 packet_info[0]
```

### INPUT-2: parse_state (unsigned int*) 🔴 TAINTED
```
├── [L6181] debug_flow = bswap32(packet_info[13])
│   └── debug_flow 🔴 TAINTED
│
├── [L6191] MBUF_MakeMemoryContinuous_fl(..., packet_info[0], ...)
│   └── 📎 MBUF_MakeMemoryContinuous_fl (offset 参数)
│
├── [L6210] sa_lookup_key = packet_info[3]
│   └── sa_lookup_key 🔴 TAINTED
│       └── [L6212] VOS_AVL3_Find(..., &sa_lookup_key, ...)
│           └── ⚠️ DIRECT_SINK: SPI 直接控制 SA 查找键
│
├── [L6281] payload_len = packet_info[4]
│   └── payload_len 🔴 TAINTED
│       └── [L6282] payload_offset = payload_len - packet_info[0]
│           └── payload_offset 🔴 TAINTED
│               ├── [L6300] VRP_Malloc_F(..., payload_offset, ...)
│               │   └── ⚠️ DIRECT_SINK: 分配大小由污点控制
│               ├── [L6319] read_offset = packet_info[0]
│               │   └── read_offset 🔴 TAINTED
│               │       └── [L6326] LOOP: MBUF_MakeMemoryContinuous_fl(..., read_offset, chunk_len, ...)
│               │           ├── [L6235] memcpy_s(..., chunk_base, chunk_len) ⚠️ DIRECT_SINK
│               │           └── [L6502] algo_desc[7](auth_ctx, header_copy + option_offset, chunk_len)
│               └── [L6507] 写入 IP 头总长字段
│
├── [L6283] packet_info[5] = payload_offset
│   └── packet_info[5] 🔴 TAINTED (输出参数回写)
│
├── [L6284] packet_info[6] = payload_offset + 12
│   └── packet_info[6] 🔴 TAINTED (输出参数回写)
│
├── [L6298] IP 总长字段 = *(uint16_t*)(packet_info+5) + ...
│   └── ⚠️ DIRECT_SINK: 总长由污点计算
│
├── [L6390] auth_header[0] = *(packet_info+32)
│   └── auth_header[0] 🔴 TAINTED (Next Header 来自污点)
│       └── ⚠️ DIRECT_SINK: Next Header 由污点控制
│
├── [L6393] auth_header[4..7] = bswap32(packet_info[3])
│   └── auth_header[4..7] 🔴 TAINTED (SPI 写入 AH 头)
│       └── ⚠️ DIRECT_SINK: SPI 由污点写入，影响后续 SA 查找
│
├── [L6402] VRP_Malloc_F(..., packet_info[0], ...)
│   └── ⚠️ DIRECT_SINK: 分配大小由污点控制
│
├── [L6432] MBUF_CopyDataFromMBufToBuffer(..., packet_info[0], ...)
│   └── ⚠️ DIRECT_SINK: 拷贝大小由污点控制
│
├── [L6460] if (packet_info[0] < header_len)
│   └── 边界检查由污点数据参与
│
└── [L6547, L6559] MBUF_CopyDataFromBufferToMBuf(..., packet_info[0], ...)
    └── ⚠️ DIRECT_SINK: 偏移由污点控制
```

---

## 新引入的污点对象 (Within Current Function)

| 对象名 | 行号 | 来源函数/操作 | 类型 |
|--------|------|---------------|------|
| `ip_header` | L6188 | MBUF_MakeMemoryContinuous_fl | 返回值 |
| `chunk_base` | L6229 | MBUF_MakeMemoryContinuous_fl (循环) | 返回值 |
| `header_copy` | L6467 | MBUF_CopyDataFromMBufToBuffer | 输出参数 |
| `payload_copy` | L6235 | memcpy_s | 拷贝结果 |
| `auth_header` | L6390 | 分配+写入 parse_state 数据 | 局部缓冲区 |
| `sa_lookup_key` | L6210 | packet_info[3] 赋值 | 派生值 |
| `payload_len` | L6281 | packet_info[4] 赋值 | 派生值 |
| `payload_offset` | L6282 | payload_len - packet_info[0] | 计算值 |
| `read_offset` | L6319 | packet_info[0] 赋值 | 派生值 |
| `debug_flow` | L6181 | bswap32(packet_info[13]) | 派生值 |

---

## 污点终点汇总

| 脏数据 | 终点类型 | 位置 | 说明 |
|--------|---------|------|------|
| `mbuf_base` | ⚠️ DIRECT_SINK | L6235 | memcpy: 污点指针+污点大小控制拷贝 |
| `mbuf_base` | ⚠️ DIRECT_SINK | L6498 | header_copy[option_offset+1] 控制解析进度 |
| `mbuf_base` | ⚠️ DIRECT_SINK | L6508 | header_copy[0]&0xF 控制循环边界 |
| `mbuf_base` | ⚠️ DIRECT_SINK | L6513 | MBUF_PrependMemorySpace 重新分配 |
| `mbuf_base` | ⚠️ DIRECT_SINK | L6529 | 污点数据写回 mbuf |
| `mbuf_base` | ⚠️ DIRECT_SINK | L6547 | auth_header(含mbuf数据) 写入mbuf |
| `chunk_base` | ⚠️ DIRECT_SINK | L6235 | memcpy_s: chunk_len 大小来自污点 |
| `header_copy` | ⚠️ DIRECT_SINK | L6529 | 污点数据写回 mbuf |
| `parse_state[0]` | ⚠️ DIRECT_SINK | L6191, L6326 | 偏移/大小参数传入内存操作 |
| `parse_state[3]` | ⚠️ DIRECT_SINK | L6212 | SPI 直接控制 SA 查找键 |
| `parse_state[4]` | ⚠️ DIRECT_SINK | L6300 | payload_offset 控制分配大小 |
| `parse_state[3]` | ⚠️ DIRECT_SINK | L6393 | SPI 写入 AH 头，影响后续 SA 查找 |
| `parse_state[32]` | ⚠️ DIRECT_SINK | L6390 | Next Header 由污点控制 |
| `parse_state[0]` | ⚠️ DIRECT_SINK | L6402 | packet_info[0] 控制分配大小 |
| `parse_state[0]` | ⚠️ DIRECT_SINK | L6432 | packet_info[0] 控制拷贝大小 |
| `parse_state[0]` | ⚠️ DIRECT_SINK | L6547, L6559 | packet_info[0] 控制写回偏移 |
| `payload_len/payload_offset` | ⚠️ DIRECT_SINK | L6507 | 总长字段由污点计算并写入 |
| `packet_info[5]` | ⚠️ DIRECT_SINK | L6298 | 总长由污点计算 |

---

## 外部库函数标记

| 函数 | 行号 | 说明 |
|------|------|------|
| `MBUF_MakeMemoryContinuous_fl` | L6188, L6191, L6229, L6326, L6519, L6522 | 外部内存连续化库函数 🟡 EXPORT |
| `MBUF_CopyDataFromMBufToBuffer` | L6467, L6432 | 外部内存拷贝库函数 🟡 EXPORT |
| `MBUF_CopyDataFromBufferToMBuf` | L6529, L6547, L6559 | 外部内存拷贝库函数 🟡 EXPORT |
| `MBUF_PrependMemorySpace_fl` | L6513 | 外部内存重分配库函数 🟡 EXPORT |
| `memcpy_s` | L6235, L6534 | 标准库函数 🟡 EXPORT |