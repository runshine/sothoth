## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_PKT_ParseAndVerifyHdrV4

## 函数信息
- **文件**: libipsec.c
- **签名**: `int IPSEC_PKT_ParseAndVerifyHdrV4(..., int64_t mbuf, packet_state packet_state, ...)`

## 污点源

| ID | 参数 | 类型 | 状态 | 说明 |
|----|------|------|------|------|
| INPUT-1 | mbuf | int64_t | 🔴 TAINTED | 外部网络数据包缓冲区 |
| INPUT-2 | packet_state | packet_state | 🔴 TAINTED | 外部网络输入的状态结构体指针 |

---

## 新导入的污点对象

| ID | 对象 | 类型 | 导入方式 | 行号 |
|----|------|------|----------|------|
| NEW-1 | ip_header | uint8_t* | MBUF_MakeMemoryContinuous_fl 提取 | L11191 |
| NEW-2 | total_data_len | int | MBUF_GetTotalDataLength 读取 | L11226 |
| NEW-3 | esp_header | uint32_t* | MBUF_MakeMemoryContinuous_fl 提取 | L11259 |
| NEW-4 | ah_header | int64_t | MBUF_MakeMemoryContinuous_fl 提取 | L11329 |
| NEW-5 | state | uint8_t* | (uint8_t*)packet_state 类型转换 | L11168 |

---

## 数据流树状图

### INPUT-1: mbuf (int64_t) 🔴 TAINTED
```
[L11191] MBUF_MakeMemoryContinuous_fl(mbuf, 0, 20, ...)
  └── ip_header 🔴 TAINTED (NEW-1)
      ├── [L11204] version_nibble = ip_header[0] → version_nibble 🔴 TAINTED
      │   └── [L11218] header_len = 4 * (version_nibble & 0xF) → header_len 🔴 TAINTED
      │       ├── [L11259] esp_header = MBUF_MakeMemoryContinuous_fl(mbuf, header_len, ...)
      │       │   ├── esp_header 🔴 TAINTED (NEW-3) ⚠️ DIRECT_SINK: offset/size 由污点控制
      │       │   └── [L11278] SPI = bswap32(*esp_header)
      │       └── [L11329] ah_header = MBUF_MakeMemoryContinuous_fl(mbuf, header_len, ...)
      │           ├── ah_header 🔴 TAINTED (NEW-4) ⚠️ DIRECT_SINK: offset/size 由污点控制
      │           └── [L11347] SPI = bswap32(RAW_U32(ah_header, 4))
      ├── [L11243] IPSEC_LIB_Ipv4AddrToStr(ip_header[12], src_addr_text, 16) 📎
      └── [L11243] IPSEC_LIB_Ipv4AddrToStr(ip_header[16], dst_addr_text, 16) 📎

[L11226] total_data_len = MBUF_GetTotalDataLength(mbuf) → total_data_len 🔴 TAINTED (NEW-2)
  └── [L11228] RAW_U32(state, PST_TOTAL_LEN) = total_data_len

[L11239] next_proto = ip_header[9] → next_proto 🔴 TAINTED
  └── [L11376] RAW_U8(state, PST_NEXT_PROTO) = (uint8_t)next_proto

[L11248] dst_ipv4 = bswap32(ip_header[16]) → dst_ipv4 🔴 TAINTED
  └── [L11253] RAW_U32(state, PST_DST4_RAW) = dst_ipv4
```

### INPUT-2: packet_state (packet_state) 🔴 TAINTED
```
[L11168] state = (uint8_t*)packet_state → state 🔴 TAINTED (NEW-5)
  ├── [L11217] if (RAW_U8(state, PST_OUTPUT_FLAG) == 1) — 仅读取
  ├── [L11218] RAW_U16(state, PST_PACKET_LEN) = __builtin_bswap16(...) — 写入
  ├── [L11224] packet_len_field = RAW_U16(state, PST_PACKET_LEN) — 读取
  ├── [L11225] RAW_U32(state, PST_TOTAL_LEN) = total_data_len — 写入
  ├── [L11276] if (RAW_U8(state, PST_OUTPUT_FLAG) != 0) — 仅读取
  ├── [L11293] MBUF_MakeMemoryContinuous_fl(mbuf, header_len, RAW_U32(state, PST_TOTAL_LEN) - header_len, ...)
  │   └── ⚠️ DIRECT_SINK: 长度参数由污点数据决定
  ├── [L11306] RAW_U8(state, PST_PROTO) = 50 — 写入
  ├── [L11307] RAW_U32(state, PST_HDR_OFFSET) = header_len — 写入
  ├── [L11308] RAW_U32(state, PST_SPI) = __builtin_bswap32(*esp_header) — 写入
  ├── [L11309] IPSEC_PKT_DebugPacketV4(..., RAW_U32(state, PST_PKT_KIND)) 📎
  ├── [L11310] IPSEC_LIBI_GetManualSa(lib_ctx, packet_state, 0) 📎
  ├── [L11297] IPSEC_MakeDbgLibStrSetter(..., RAW_U32(state, PST_SPI), ...) 📎
  ├── [L11354] if (RAW_U8(state, PST_OUTPUT_FLAG) != 0) — 仅读取
  ├── [L11361] IPSEC_MakeDbgLibStrSetter(..., RAW_U32(state, PST_SPI), ...) 📎
  ├── [L11391] RAW_U8(state, PST_PROTO) = 51 — 写入
  ├── [L11392] RAW_U32(state, PST_HDR_OFFSET) = header_len — 写入
  ├── [L11393] RAW_U32(state, PST_SPI) = ... — 写入
  ├── [L11413] RAW_U32(state, PST_SPI) — 读取
  ├── [L11428] RAW_U32(state, PST_SPI) — 读取
  ├── [L11454] if (RAW_U8(state, PST_OUTPUT_FLAG) == 0) — 仅读取
  ├── [L11459] IPSEC_PKT_DebugPacketV4(..., RAW_U32(state, PST_PKT_KIND)) 📎
  ├── [L11464] IPSEC_PKT_DebugPacketV4(..., RAW_U32(state, PST_PKT_KIND)) 📎
  ├── [L11476] RAW_U8(state, PST_NEXT_PROTO) = (uint8_t)next_proto — 写入
  └── [L11477] RAW_U32(state, PST_HDR_OFFSET) = header_len — 写入
```

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf | 📎 USED | L11191, L11259, L11329 | MBUF_MakeMemoryContinuous_fl 提取数据 |
| ip_header | 📎 USED | L11243 | IPSEC_LIB_Ipv4AddrToStr 地址转字符串 |
| esp_header | ⚠️ DIRECT_SINK | L11259 | offset/size 由污点 header_len 控制 |
| ah_header | ⚠️ DIRECT_SINK | L11329 | offset/size 由污点 header_len 控制 |
| state | ⚠️ DIRECT_SINK | L11293 | MBUF_MakeMemoryContinuous_fl 长度参数来自污点 |

---

## 高危 DIRECT_SINK

| 模式 | 位置 | 说明 |
|------|------|------|
| MBUF_MakeMemoryContinuous_fl offset/size 可控 | L11259, L11329 | esp_header/ah_header 提取由 header_len 控制 |
| MBUF_MakeMemoryContinuous_fl 长度参数可控 | L11293 | PST_TOTAL_LEN 由 total_data_len 写入 |

---

## 子函数跟入表

| 函数 | 行号 | 污点参数 | 来源 |
|------|------|----------|------|
| MBUF_MakeMemoryContinuous_fl | L11191 | mbuf | INPUT-1 |
| MBUF_GetTotalDataLength | L11226 | mbuf | INPUT-1 |
| MBUF_MakeMemoryContinuous_fl | L11259 | mbuf | INPUT-1 |
| MBUF_MakeMemoryContinuous_fl | L11329 | mbuf | INPUT-1 |
| IPSEC_LIB_Ipv4AddrToStr | L11243 | ip_header | NEW-1 |
| IPSEC_LIBI_GetManualSa | L11280, L11310 | packet_state | INPUT-2 |
| IPSEC_PKT_DebugPacketV4 | L11309,L11315,L11373,L11380,L11459,L11464 | PST_PKT_KIND | NEW-5 |
| IPSEC_MakeDbgLibStrSetter | L11297,L11300,L11361,L11364 | PST_SPI | NEW-5 |