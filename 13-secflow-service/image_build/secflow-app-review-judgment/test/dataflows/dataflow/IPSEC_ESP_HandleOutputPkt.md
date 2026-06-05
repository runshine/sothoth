## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_ESP_HandleOutputPkt

## 函数信息
- 文件: `libipsec.c`
- 签名: `IPSEC_ESP_HandleOutputPkt(int a, int b, unsigned int *parse_state, void *mbuf, void *c, void *d)`

---

## 污点源

| 标识 | 变量 | 类型 | 说明 |
|------|------|------|------|
| INPUT-1 | `mbuf` | `void*` | 🔴 TAINTED — 外部网络数据包缓冲区（ESP outbound packet） |
| INPUT-2 | `parse_state` | `unsigned int*` | 🔴 TAINTED — 外部指针，被强转为 `packet_info` 使用 |

---

## 污点传播树状图

### INPUT-1: `mbuf` (void*) 🔴 TAINTED
```
├── [L8368] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...)
│   → ip_header 🔴 TAINTED (新导入对象)
│   ├── [L8470] RAW_U8((void*)ip_header, packet_info[1]) = 50
│   └── [L8474] RAW_U16((void*)ip_header, 4) = ...
│
├── [L8491] appended_tail = (uint8_t*)MBUF_AppendMemorySpace_fl(mbuf, auth_and_tail_len, ...)
│   → appended_tail 🔴 TAINTED (新导入对象)
│   ├── [L8500] appended_tail[copy_offset] = (uint8_t)(copy_offset + 1)
│   ├── [L8501] appended_tail[pad_len] = (uint8_t)(tail_len - 2)
│   ├── [L8502] appended_tail[pad_len + 1] = *((uint8_t*)packet_info + 32)
│   └── [L8721] memcpy_s(appended_tail + tail_len, auth_hash_len, auth_result, auth_hash_len)
│       └── appended_tail 作为 memcpy 目标，接收干净数据
│
├── [L8551] chunk = MBUF_MakeMemoryContinuous_fl(mbuf, copy_offset, copy_len, ...) [循环]
│   → chunk 🔴 TAINTED (新导入对象)
│   ├── [L8560] block_ptr = (uint8_t*)chunk
│   │   → block_ptr 🔴 TAINTED (新导入对象)
│   │   ├── [L8565] callback(sa_entry, block_ptr, copy_len)
│   │   │   └── ⚠️ DIRECT_SINK: copy_len 来自 packet_info[6]（外部输入）
│   │   ├── [L8566-L8567] auth_desc[7](auth_ctx, block_ptr, enc_block_size)
│   │   └── [L8569] memcpy_s((void*)(sa_entry+80), 16, block_ptr, iv_len)
│   │       └── ⚠️ DIRECT_SINK: block_ptr 来自 mbuf-derived chunk，iv_len 来自 SA 字段
│   └── [L8589] auth_desc[7](auth_ctx, (const void*)chunk, copy_len)
│
├── [L8698] MBUF_PrependMemorySpace_fl(mbuf, iv_len + 8, ...)
│   └── ⚠️ DIRECT_SINK: 扩展大小参数 iv_len 来自污点关联的 SA 字段
│
├── [L8704] MBUF_MakeMemoryContinuous_fl(mbuf, 0, iv_len + 8 + *packet_info, ...)
│   └── ⚠️ DIRECT_SINK: 内存连续化大小包含污点 iv_len 和 *packet_info
│
├── [L8709] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, *packet_info, scratch_buf)
│   → mbuf 作为源参数（读取数据）
│
├── [L8713] MBUF_PrependMemorySpace_fl(mbuf, iv_len + 8, ...)
│   └── ⚠️ DIRECT_SINK: 扩展大小参数 iv_len 来自污点关联的 SA 字段
│
├── [L8719] MBUF_MakeMemoryContinuous_fl(mbuf, 0, iv_len + 8 + *packet_info, ...)
│   └── ⚠️ DIRECT_SINK: 内存连续化大小包含污点 iv_len 和 *packet_info
│
├── [L8722] MBUF_CopyDataFromBufferToMBuf(mbuf, 0, *packet_info, scratch_buf, ...)
│   → mbuf 作为目标参数（接收干净数据）
│
└── [L8726] MBUF_CopyDataFromBufferToMBuf(mbuf, *packet_info, iv_len + 8, &esp_hdr[0], ...)
    └── ⚠️ DIRECT_SINK: 写入偏移 *packet_info 和长度 iv_len+8 都由外部输入/SA 控制
```

---

### INPUT-2: `parse_state` → `packet_info` (unsigned int*) 🔴 TAINTED
```
├── [L8374] selector_pair = ((uint64_t)packet_info[10]<<32) | packet_info[9] → selector_pair 🔴 TAINTED (新导入对象)
│   └── [L8417] VOS_AVL3_Find(..., &selector_pair_hi, ...)
│       ├── [L8438] IPSEC_PKT_DebugPacket(..., selector_pair, ...)
│       ├── [L8440] IPSEC_PKT_DebugPacket(..., selector_pair, ...)
│       ├── [L8629] IPSEC_PKT_DebugPacket(..., selector_pair, ...)
│       └── [L8708] IPSEC_PKT_DebugPacket(..., selector_pair, ...)
│
├── [L8375] selector_pair_hi = ((uint64_t)packet_info[12]<<32) | packet_info[11] → selector_pair_hi 🔴 TAINTED (新导入对象)
│   ├── [L8405] RAW_U32(&selector_pair_hi,0) = packet_info[3]
│   └── [L8417] VOS_AVL3_Find(..., &selector_pair_hi, ...) → 📎 见跟入列表
│
├── [L8368] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...)
│   └── ⚠️ DIRECT_SINK: *packet_info 控制内存分配大小
│
├── [L8442] algo_dbg_word = packet_info[14] → algo_dbg_word 🔴 TAINTED (新导入对象)
│   ├── [L8443] IPSECL_DBG_EspPktAlgo(..., &algo_dbg_word) → 📎 见跟入列表
│   └── [L8450] IPSECL_DBG_EspPktAlgo(..., &algo_dbg_word) → 📎 见跟入列表
│
├── [L8457] payload_len = packet_info[4] → payload_len 🔴 TAINTED
├── [L8458] payload_offset = payload_len - *packet_info → payload_offset 🔴 TAINTED
├── [L8459] packet_info[5] = payload_offset → packet_info[5] 🔴 TAINTED
├── [L8444] enc_block_size = RAW_U16(enc_desc, 12) → enc_block_size 🔴 TAINTED
├── [L8460] pad_len = ... % enc_block_size → pad_len 🔴 TAINTED (依赖污点 payload_offset)
│   └── [L8509-8512] for(copy_offset=0; copy_offset<pad_len; ...) appended_tail[copy_offset]
│       └── ⚠️ DIRECT_SINK: 循环边界来自污点 pad_len
├── [L8461] tail_len = pad_len + 2 → tail_len 🔴 TAINTED
│   └── [L8511] appended_tail[pad_len] = (uint8_t)(tail_len - 2)
│   └── [L8512] appended_tail[pad_len + 1] = *((uint8_t*)packet_info + 32)
│       └── ⚠️ DIRECT_SINK: 污点 tail_len 控制下标
├── [L8462] auth_and_tail_len = auth_hash_len + tail_len → auth_and_tail_len 🔴 TAINTED
├── [L8463] new_packet_len = payload_len + iv_len + 8 + auth_and_tail_len → new_packet_len 🔴 TAINTED
├── [L8464] *((uint8_t*)packet_info + 29) = (uint8_t)tail_len → packet_info[29] 🔴 TAINTED
├── [L8465] packet_info[6] = iv_len + 8 + payload_offset + tail_len → packet_info[6] 🔴 TAINTED
│   ├── [L8549] copy_len = packet_info[6] - iv_len - 8 - auth_hash_len - processed → copy_len 🔴 TAINTED
│   │   └── [L8551] chunk = MBUF_MakeMemoryContinuous_fl(mbuf, copy_offset, copy_len, ...)
│   │       └── ⚠️ DIRECT_SINK: 污点 copy_len 控制内存块大小
│   └── [L8562] 循环遍历 chunk 加密 auth
│
├── [L8445] *((uint8_t*)packet_info + 30) = RAW_U16(sa_entry, 28) → packet_info[30] 🔴 TAINTED
├── [L8446] *((uint8_t*)packet_info + 31) = enc_block_size → packet_info[31] 🔴 TAINTED
│
├── [L8514] esp_hdr[0] = __builtin_bswap32(packet_info[3]) → esp_hdr[0] 🔴 TAINTED (新导入对象)
│   └── [L8528] auth_desc[7](auth_ctx, &esp_hdr[0], iv_len+8)
│
├── [L8537] copy_offset = *packet_info → copy_offset 🔴 TAINTED
│   └── [L8551] MBUF_MakeMemoryContinuous_fl(mbuf, copy_offset, copy_len, ...)
│       └── ⚠️ DIRECT_SINK: 污点 copy_offset 控制内存读取起点
│
├── [L8628] scratch_buf = VRP_Malloc_F(..., *packet_info, ...)
│   └── ⚠️ DIRECT_SINK: *packet_info 污点大小控制堆分配
├── [L8644] scratch_buf = VRP_Malloc_F(..., *packet_info, ...)
│   └── ⚠️ DIRECT_SINK: *packet_info 污点大小控制堆分配
│
├── [L8663] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, *packet_info, scratch_buf)
│   └── ⚠️ DIRECT_SINK: *packet_info 污点大小控制复制字节数
├── [L8688] MBUF_MakeMemoryContinuous_fl(mbuf, 0, iv_len + 8 + *packet_info, ...)
│   └── ⚠️ DIRECT_SINK: *packet_info 参与总大小计算
├── [L8699] MBUF_CopyDataFromBufferToMBuf(mbuf, 0, *packet_info, scratch_buf, ...)
│   └── ⚠️ DIRECT_SINK: *packet_info 污点大小控制复制
└── [L8700] MBUF_CopyDataFromBufferToMBuf(mbuf, *packet_info, iv_len + 8, &esp_hdr[0], ...)
    └── ⚠️ DIRECT_SINK: *packet_info 污点偏移控制写入位置
```

---

## 新导入的污点载体对象（在当前函数内派生）

| 变量名 | 派生位置 | 派生来源 | 说明 |
|--------|---------|---------|------|
| `ip_header` | L8368 | `MBUF_MakeMemoryContinuous_fl()` 返回 | 🔴 TAINTED |
| `appended_tail` | L8491 | `MBUF_AppendMemorySpace_fl()` 返回 | 🔴 TAINTED |
| `chunk` | L8551 | `MBUF_MakeMemoryContinuous_fl()` 返回（循环内） | 🔴 TAINTED |
| `block_ptr` | L8560 | `(uint8_t*)chunk` 派生 | 🔴 TAINTED |
| `selector_pair` | L8374 | `packet_info[10,9]` 组合 | 🔴 TAINTED |
| `selector_pair_hi` | L8375 | `packet_info[12,11]` 组合 | 🔴 TAINTED |
| `algo_dbg_word` | L8442 | `packet_info[14]` 提取 | 🔴 TAINTED |
| `esp_hdr[0]` | L8514 | `bswap32(packet_info[3])` | 🔴 TAINTED |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `mbuf` | MBUF_MakeMemoryContinuous_fl | L8368 | 控制 mbuf 数据区域访问 |
| `mbuf` | MBUF_AppendMemorySpace_fl | L8491 | ESP padding 数据写入 |
| `mbuf` | MBUF_MakeMemoryContinuous_fl | L8551 | 数据加密处理（copy_len 受控） |
| `mbuf` | MBUF_PrependMemorySpace_fl | L8698 | prepend 大小 iv_len+8 可控 |
| `mbuf` | MBUF_MakeMemoryContinuous_fl | L8704 | 内存连续化大小可控 |
| `mbuf` | MBUF_CopyDataFromBufferToMBuf | L8726 | 写入位置和大小受污点控制 |
| `packet_info[1]` | RAW_U8 | L8476 | IP 头字段写入偏移受控 |
| `pad_len` | appended_tail[...] 循环 | L8509-8512 | padding 写入循环边界可控 |
| `packet_info[3]` | esp_hdr[0] = bswap32(...) | L8514 | ESP SPI 字段写入 |
| `copy_len` | MBUF_MakeMemoryContinuous_fl | L8551 | 内存块大小受控 |
| `*packet_info` | VRP_Malloc_F | L8628, L8644 | 堆分配大小可控 |
| `*packet_info` | MBUF_CopyDataFromMBufToBuffer | L8663 | 数据复制大小可控 |
| `*packet_info` | MBUF_CopyDataFromBufferToMBuf | L8699, L8700 | 数据复制大小/偏移可控 |

---

## 关键 DIRECT_SINK 汇总

| 行号 | 危险操作 | 污点来源 |
|------|---------|---------|
| L8476 | `RAW_U8((void*)ip_header, packet_info[1]) = 50` | `packet_info[1]` 污点下标 |
| L8509-8512 | `appended_tail[copy_offset/pad_len+1]` 循环写入 | `pad_len` 来自污点 `payload_offset` |
| L8514 | `esp_hdr[0] = bswap32(packet_info[3])` | `packet_info[3]` 污点 SPI 写入数据包头 |
| L8551 | `MBUF_MakeMemoryContinuous_fl(..., copy_len, ...)` | `copy_len` 来自 `packet_info[6]` |
| L8628, L8644 | `VRP_Malloc_F(..., *packet_info, ...)` | `*packet_info` 控制堆分配大小 |
| L8663 | `MBUF_CopyDataFromMBufToBuffer(..., *packet_info, ...)` | `*packet_info` 控制复制大小 |
| L8699 | `MBUF_CopyDataFromBufferToMBuf(..., *packet_info, ...)` | `*packet_info` 控制复制大小 |
| L8700 | `MBUF_CopyDataFromBufferToMBuf(mbuf, *packet_info, ...)` | `*packet_info` 作为目标偏移量 |
| L8688 | `MBUF_MakeMemoryContinuous_fl(..., iv_len+8+*packet_info, ...)` | `*packet_info` 参与总大小计算 |