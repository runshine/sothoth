## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: RAW_U8

## 函数信息
- 文件: libipsec.c
- 函数类型: 宏/内联函数 (内存写入操作)
- 污点接收参数: packet_info[1] - 作为指针偏移量传入

## 数据流树状图

### INPUT-1: packet_info[1] (parse_state[4..7]) 🔴 TAINTED
├── parse_state ← 🔴 TAINTED (网络数据，由 IPSEC_PKT_ParseAndVerifyHdr 填充)
│   └── parse_state[4..7] = PST_LAST_EXT_OFFSET ← 🔴 TAINTED (偏移量字段)
│       └── packet_info[1] = parse_state[4..7] ← 🔴 TAINTED
│           ├── [L5323] RAW_U8(ip_header, packet_info[1]) = 51
│           │   └── ⚠️ DIRECT_SINK: 污点偏移量控制指针，越界写入风险
│           ├── [L6074] RAW_U8(ip_header, packet_info[1]) = ah_header[0]
│           │   └── ⚠️ DIRECT_SINK: 污点偏移量控制指针，越界写入风险
│           ├── [L8485] RAW_U8(ip_header, packet_info[1]) = 50
│           │   └── ⚠️ DIRECT_SINK: 污点偏移量控制指针，越界写入风险
│           ├── [L9695] RAW_U8(ip_header, packet_info[1]) = esp_tail_block[enc_block_size-1]
│           │   └── ⚠️ DIRECT_SINK: 污点偏移量控制指针，越界写入风险
│           └── [L9697] RAW_U8(ip_header, packet_info[1]) = next_header
│               └── ⚠️ DIRECT_SINK: 污点偏移量控制指针，越界写入风险
│
└── 传播路径来源:
    ├── [L10446] offset += 8 * (ext_header[1] + 1) → offset 🔴 TAINTED (ext_header[1]来自网络)
    ├── [L10494] RAW_U32(state, PST_LAST_EXT_OFFSET) = offset → state[4..7] 🔴 TAINTED
    ├── [L10646] RAW_U32(state, PST_LAST_EXT_OFFSET) = offset → 污点传播
    ├── [L10690] RAW_U32(state, PST_LAST_EXT_OFFSET) = offset → 污点传播
    └── [L10713] RAW_U32(state, PST_LAST_EXT_OFFSET) = offset → 污点传播

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| packet_info[1] | RAW_U8(ip_header, packet_info[1]) | L5323 | ⚠️ DIRECT_SINK: AH输出处理，污点偏移写入 |
| packet_info[1] | RAW_U8(ip_header, packet_info[1]) | L6074 | ⚠️ DIRECT_SINK: AH输入处理，污点偏移写入 |
| packet_info[1] | RAW_U8(ip_header, packet_info[1]) | L8485 | ⚠️ DIRECT_SINK: ESP输出处理，污点偏移写入 |
| packet_info[1] | RAW_U8(ip_header, packet_info[1]) | L9695 | ⚠️ DIRECT_SINK: ESP输入处理，污点偏移写入 |
| packet_info[1] | RAW_U8(ip_header, packet_info[1]) | L9697 | ⚠️ DIRECT_SINK: ESP输入处理，污点偏移写入 |

## 子函数跟入列表 (接收污点数据)

| 调用函数 | 位置 | 接收的污点参数 |
|----------|------|----------------|
| IPSEC_PKT_ParseAndVerifyHdr | L10386 | mbuf, lib_ctx, packet_state |
| IPSEC_LIBI_GetManualSa | L10855 | lib_ctx, parse_state |
| IPSEC_AH_HandleInputPkt | L11062 | lib_ctx, mbuf, packet_info |
| IPSEC_AH_HandleOutputPkt | L10868 | lib_ctx, mbuf, packet_info |
| IPSEC_ESP_HandleInputPkt | L11085 | lib_ctx, mbuf, packet_info |
| IPSEC_ESP_HandleOutputPkt | L10897 | lib_ctx, mbuf, packet_info |