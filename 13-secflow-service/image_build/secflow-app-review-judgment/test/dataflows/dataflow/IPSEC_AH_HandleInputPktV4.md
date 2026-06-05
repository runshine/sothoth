## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `lib_ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `packet_info` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `stats_ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_AH_HandleInputPktV4

## 函数信息
- 文件: libipsec.c
- 签名: `int IPSEC_AH_HandleInputPktV4(void *lib_ctx_base, void *stats_ctx_base, void *mbuf, unsigned int *packet_info)`
- 外部输入参数:
  - `lib_ctx_base` — IPsec库上下文句柄
  - `stats_ctx_base` — IPsec SA统计上下文指针
  - `mbuf` — 网络数据包
  - `packet_info` — 数据包元信息数组

---

## 污点源汇总

| ID | 变量 | 类型 | 说明 |
|----|------|------|------|
| INPUT-1 | `lib_ctx_base` | int64_t | IPsec库上下文句柄，外部输入 |
| INPUT-2 | `stats_ctx_base` | int64_t | IPsec SA统计上下文指针，外部输入 |
| INPUT-3 | `mbuf` | void* | 网络数据包，来自IPv4入站流量 |
| INPUT-4 | `packet_info` | unsigned int* | 数据包元信息数组，外部网络输入 |

---

## 传播路径

### INPUT-1: lib_ctx_base (int64_t) 🔴 TAINTED
```
├── [L6718] NULL检查 → 干净
├── [L6724] MBUF_MakeMemoryContinuous_fl(..., RAW_U64(lib_ctx,16), ...) → mem_ops 🔴 TAINTED
├── [L6737] MBUF_MakeMemoryContinuous_fl(..., RAW_U64(lib_ctx,16), ...) → mem_ops 🔴 TAINTED
├── [L6760] if(RAW_U8(lib_ctx,400)==1||RAW_U8(lib_ctx,403)==1) → debug_flag 🔴 TAINTED (条件判断)
├── [L6770] VOS_AVL3_Find(lib_ctx+120, &sa_key, lib_ctx+144) → 📎 子函数
├── [L6791] VOS_AVL3_Find(lib_ctx+76, ..., lib_ctx+100) → 📎 子函数
├── [L6823] VRP_Malloc_F(RAW_U64(lib_ctx,8), ...) → mem_pool 🔴 TAINTED
│   └── 分配 header_copy → [L6850] MBUF_CopyDataFromMBufToBuffer → USED
├── [L6827-6846] SSP_Debug(..., (char*)(lib_ctx+448)) → 📎 子函数 (调试字符串)
├── [L6828-6847] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L6936] VRP_Malloc_F(RAW_U64(lib_ctx,8), ...) → mem_pool 🔴 TAINTED
│   └── 分配 payload_copy → [L7003] memcpy_s(payload_copy, ...) → USED
├── [L6943-6964] SSP_Debug(..., (char*)(lib_ctx+448)) → 📎 子函数
├── [L6944-6965] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L6983] MBUF_MakeMemoryContinuous_fl(..., RAW_U64(lib_ctx,16), ...) → mem_ops 🔴 TAINTED
├── [L6990] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 日志 (不传递)
├── [L7019-7054] SSP_Debug(..., (char*)(lib_ctx+448)) → 📎 子函数
├── [L7020-7055] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L7057] algo_desc[9](computed_auth, auth_ctx, lib_ctx, 64) → 📎 子函数 (认证计算)
├── [L7066] algo_desc[9](computed_auth, auth_ctx, lib_ctx, 64) → 📎 子函数
├── [L7070] IPSEC_PKT_DebugPacketV4(lib_ctx, sadb_entry, ...) → 📎 子函数
├── [L7085] IPSEC_PKT_DebugPacketV4(lib_ctx, sadb_entry, ...) → 📎 子函数
├── [L7086-7088] SSP_Debug(..., (char*)(lib_ctx+448)) → 📎 子函数
├── [L7087] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
└── [L7102] MBUF_CreateControlInfo_fl(mbuf, 10, 8, RAW_U64(lib_ctx,16), ...) → ⚠️ DIRECT_SINK
```

#### 派生: mem_pool 🔴 TAINTED
- [L6823,L6936] VRP_Malloc_F(mem_pool, ...) → 分配包数据缓冲区

#### 派生: mem_ops 🔴 TAINTED
- [L6724,L6737,L6983] MBUF_MakeMemoryContinuous_fl(..., mem_ops, ...) → 内存连续化
- [L7102] MBUF_CreateControlInfo_fl(..., mem_ops, ...) → ⚠️ DIRECT_SINK

---

### INPUT-2: stats_ctx_base (int64_t) 🔴 TAINTED
```
├── [L6743] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, 0, 28, 0) → 🟡 EXPORT (错误路径)
├── [L6759] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, 0, 28, 0) → 🟡 EXPORT (错误路径)
├── [L6784] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 5, 0) → 🟡 EXPORT (错误路径)
├── [L6798] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 5, 0) → 🟡 EXPORT (错误路径)
├── [L6805] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 24, 0) → 🟡 EXPORT (错误路径)
├── [L6819] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 6, 0) → 🟡 EXPORT (错误路径)
├── [L6873] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 28, 0) → 🟡 EXPORT (错误路径)
├── [L7082] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 8, 0) → 🟡 EXPORT (错误路径)
├── [L7096] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 28, 0) → 🟡 EXPORT (错误路径)
├── [L7105] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 28, 0) → 🟡 EXPORT (错误路径)
└── [L7111] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 21, packet_info[6]) → 🟡 EXPORT
    └── ⚠️ DIRECT_SINK: packet_info[6] 写入统计上下文
```

---

### INPUT-3: mbuf (void*) 🔴 TAINTED
```
├── [L6734] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...)
│   └── ip_header 🔴 TAINTED
│       ├── [L6754] ip_header_len = 4u * (RAW_U8(ip_header,0) & 0xF) → ip_header_len 🔴 TAINTED
│       │   └── [L6755] ah_header = (uint8_t*)(ip_header + ip_header_len)
│       │       ├── ⚠️ DIRECT_SINK: 指针运算，偏移量ip_header_len来自mbuf
│       │       ├── [L6805] 4u * ah_header[1] (uint8_t→uint32截断)
│       │       ├── [L6765] ah_spi_host = *(uint32_t*)(ah_header+4)
│       │       ├── [L6869] algo_desc[7](auth_ctx, header_copy, 20)
│       │       └── [L6927] algo_desc[7](auth_ctx, ah_header, 12)
│       └── [L6928] algo_desc[7](auth_ctx, &g_aucIpsecZeroes, auth_hash_len)
├── [L6746] MBUF_MakeMemoryContinuous_fl(mbuf, *packet_info, packet_info[4]-*packet_info, ...)
├── [L6820] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, *packet_info, header_copy)
│   └── header_copy 🔴 TAINTED
│       ├── [L6879-6904] 循环解析IP options: header_copy[offset], header_copy[offset+1] 🔴 TAINTED
│       └── ⚠️ DIRECT_SINK: option_offset/option_len来自mbuf数据
├── [L6973] read_offset = payload_offset (auth_hash_len+12+*packet_info) → read_offset 🔴 TAINTED
├── [L6977] chunk_base = MBUF_MakeMemoryContinuous_fl(mbuf, read_offset, chunk_len, ...)
│   └── chunk_base 🔴 TAINTED
│       ├── [L6987] memcpy_s(payload_copy, chunk_base, chunk_len)
│       │   └── ⚠️ DIRECT_SINK: 大小chunk_len和源指针chunk_base均来自mbuf
│       └── payload_copy 🔴 TAINTED
│           └── [L7027] algo_desc[7](auth_ctx, payload_copy, payload_len)
├── [L7038] VOS_MemCmp(computed_auth, ah_header+12, auth_hash_len) (认证校验)
├── [L7065] MBUF_CheckSum(mbuf, ip_header_len)
├── [L7067] MBUF_CutPart_fl(mbuf, *packet_info, auth_hash_len+12, ...)
├── [L7076] MBUF_CreateControlInfo_fl(mbuf, 10, 8, ...)
├── [L7090] MBUF_SetFlag(mbuf, 0x10000000)
└── [L7091] MBUF_GetControlInfo(mbuf, 10) 📌 USED
```

#### 派生: ip_header 🔴 TAINTED
- 从 mbuf 内部内存提取，受 packet_info 控制

#### 派生: ah_header 🔴 TAINTED
- 从 ip_header 偏移 ip_header_len 提取，受 mbuf 数据控制

#### 派生: header_copy 🔴 TAINTED
- MBUF_CopyDataFromMBufToBuffer 写入，接收 mbuf 数据

#### 派生: chunk_base 🔴 TAINTED
- MBUF_MakeMemoryContinuous_fl 从 mbuf 读取 payload 块

#### 派生: payload_copy 🔴 TAINTED
- memcpy_s 从 chunk_base 拷贝到 payload_copy，chunk_len 受 mbuf 数据控制

---

### INPUT-4: packet_info (unsigned int*) 🔴 TAINTED
```
├── packet_info[0] (*packet_info = IP头偏移/长度)
│   ├── [L6729] ip_offset = *packet_info → ip_offset 🔴 TAINTED
│   ├── [L6731] MBUF_MakeMemoryContinuous(mbuf, 0, *packet_info, ...) ⚠️ DIRECT_SINK
│   └── [L6823] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, *packet_info, header_copy) ⚠️ DIRECT_SINK
├── packet_info[4] (数据包总长)
│   └── [L6737] MBUF_MakeMemoryContinuous(mbuf, *packet_info, packet_info[4]-*packet_info, ...) ⚠️ DIRECT_SINK
├── packet_info[5] (AH头总长)
│   ├── [L6803] VRP_Malloc_F(..., packet_info[5], ...) ⚠️ DIRECT_SINK
│   ├── [L6823] MBUF_CopyDataFromMBufToBuffer(..., *packet_info, ...) — 拷贝包含头部长度信息的数据
│   ├── [L6860] *(header_copy+2) = __builtin_bswap16(*((uint16_t *)packet_info+5)) ⚠️ DIRECT_SINK
│   └── [L6867] ip_header.total_length = packet_info[5] - auth_hash_len - 12 ⚠️ DIRECT_SINK
│       └── → packet_info[5] 污染IPv4 total_length协议头字段
├── packet_info[5] → NEW TAINTED CARRIER
│   └── [L6827] packet_info[5] = payload_len — 污点计算结果写入输出参数
├── packet_info[6] → NEW TAINTED CARRIER
│   ├── [L6828] packet_info[6] = payload_len — 污点计算结果写入输出参数
│   └── [L7134] IPSEC_SADB_UpdateSaStatsV4(..., packet_info[6]) → 🟡 EXPORT
├── packet_info[13] → debug_flow 🔴 TAINTED
│   └── [L6729] debug_flow = __builtin_bswap32(packet_info[13])
└── packet_info[14] → NEW TAINTED CARRIER
    ├── [L7057] IPSEC_PKT_DebugPacketV4(..., packet_info[14]) → 📎 见跟入列表
    ├── [L7069] IPSEC_PKT_DebugPacketV4(..., packet_info[14]) → 📎 见跟入列表
    ├── [L7122] IPSEC_PKT_DebugPacketV4(..., packet_info[14]) → 📎 见跟入列表
    └── [L7135] IPSEC_PKT_DebugPacketV4(..., packet_info[14]) → 📎 见跟入列表
```

#### 派生: packet_info[5] (NEW CARRIER) 🔴 TAINTED
- 由污点计算赋值写入输出参数，驱动后续分配、拷贝、协议头修改

#### 派生: packet_info[6] (NEW CARRIER) 🔴 TAINTED
- 由污点计算赋值写入输出参数，传入 IPSEC_SADB_UpdateSaStatsV4

#### 派生: packet_info[14] (NEW CARRIER) 🔴 TAINTED
- 由 packet_info 读取后作为调试标签参数传入子函数

---

## ⚠️ DIRECT_SINK 汇总

| 位置 | 危险操作 | 描述 |
|------|---------|------|
| L6731 | MBUF_MakeMemoryContinuous(..., *packet_info, ...) | *packet_info 控制内存区域长度，可能访问无效内存 |
| L6737 | MBUF_MakeMemoryContinuous(..., packet_info[4]-*packet_info, ...) | 长度受污点控制 |
| L6755 | ah_header = (uint8_t*)(ip_header + ip_header_len) | 指针运算，偏移量ip_header_len来自mbuf |
| L6803 | VRP_Malloc_F(..., packet_info[5], ...) | packet_info[5] 控制堆分配大小，可能堆溢出 |
| L6823 | MBUF_CopyDataFromMBufToBuffer(..., *packet_info, ...) | *packet_info 控制拷贝数据量 |
| L6860 | *(header_copy+2) = __builtin_bswap16(*((uint16_t *)packet_info+5)) | packet_info[5] 数据写入栈缓冲区 |
| L6867 | ip_header.total_length = packet_info[5] - auth_hash_len - 12 | packet_info[5] 修改网络协议头完整性 |
| L6879-6904 | 循环解析 IP options，offset/len 来自 mbuf | header_copy 内污点驱动循环越界 |
| L6977 | MBUF_MakeMemoryContinuous_fl(mbuf, read_offset, chunk_len, ...) | read_offset 和 chunk_len 受 mbuf 数据控制 |
| L6987 | memcpy_s(payload_copy, chunk_base, chunk_len) | chunk_len 大小和 chunk_base 指针均来自 mbuf |
| L7027 | algo_desc[7](auth_ctx, payload_copy, payload_len) | payload_copy 载体和 payload_len 均来自 mbuf 解析 |
| L7057等 | IPSEC_PKT_DebugPacketV4(..., packet_info[14]) | packet_info[14] 作为调试标签传入子函数 |
| L7102 | MBUF_CreateControlInfo_fl(mbuf, 10, 8, RAW_U64(lib_ctx,16), ...) | mem_ops 来自 lib_ctx 偏移16写入 mbuf |
| L7111 | IPSEC_SADB_UpdateSaStatsV4(..., packet_info[6]) | packet_info[6] 写入统计上下文 |
| L6805 | 4u * ah_header[1] (uint8_t→uint32截断) | AH payload length 计算，截断后用于内存操作 |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| lib_ctx_base | MBUF_CreateControlInfo_fl | L7102 | mem_ops 写入 mbuf 控制信息 |
| mbuf | header_copy | L6820 | MBUF_CopyDataFromMBufToBuffer 写入栈缓冲区 |
| packet_info[5] | VRP_Malloc_F | L6803 | 控制堆分配大小 |
| packet_info[5] | header_copy | L6860 | 数据写入栈缓冲区 |
| packet_info[5] | IPv4 total_length | L6867 | 污染网络协议头字段 |
| packet_info[6] | IPSEC_SADB_UpdateSaStatsV4 | L7134 | 污点数据写入统计上下文 |
| packet_info[14] | IPSEC_PKT_DebugPacketV4 | L7057/7069/7122/7135 | 污点数据作为调试标签参数 |
| mbuf | chunk_base/payload_copy | L6977/6987 | 从 mbuf 提取并拷贝 payload 数据 |
| *packet_info | MBUF_MakeMemoryContinuous | L6731 | IP头偏移作为内存区域长度参数 |
| packet_info[4] | MBUF_MakeMemoryContinuous | L6737 | 总长控制读取区域大小 |
| stats_ctx_base | IPSEC_SADB_UpdateSaStatsV4 | L6743-L7111 | 统计上下文各错误路径汇总 |