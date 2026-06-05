## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_ESP_HandleOutputPktV4

## 函数信息
- 文件: libipsec.c
- 签名: `void IPSEC_ESP_HandleOutputPktV4(void *lib_ctx, void *mbuf, unsigned int *parse_state)`
- 功能: ESP输出数据包处理（IPv4），封装IP包为ESP格式

## 污点源

| 编号 | 变量 | 类型 | 说明 |
|------|------|------|------|
| INPUT-1 | mbuf | mbuf指针 | 外部网络数据包mbuf结构，作为函数参数传入 🔴 TAINTED |
| INPUT-2 | parse_state | uint8_t[64] | 通过packet_info指针传入，来自外部控制信息 🔴 TAINTED |

### parse_state 关键字段映射
- `packet_info[0]` = PST_HDR_OFFSET ← IP头解析值，攻击者可控
- `packet_info[3]` = esp_spi ← `__builtin_bswap32(control_info[1])`，攻击者完全可控
- `packet_info[4]` = PST_TOTAL_LEN ← 从IP头解析
- `packet_info[5]` = payload_offset ← 由污点payload_offset派生后回写
- `packet_info[6]` = iv_len+8+payload_offset+tail_len
- `packet_info[13]` = DST4_RAW ← 目的IPv4地址
- `packet_info[29]` = tail_len
- `packet_info[31]` = block_size
- `packet_info[32]` = tail_len ← 由污点payload_offset派生后回写

---

## 数据流树状图

### INPUT-1: mbuf 🔴 TAINTED
```
mbuf 🔴 TAINTED
├── [L8792] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...)
│   └── ip_header 🔴 TAINTED → 指向mbuf中的IP头数据
│       └── [L8951] 修改IP头总长度字段 ⚠️ DIRECT_SINK
├── [L8872] packet_info[4], packet_info[5], pad_len, tail_len 等派生值
│   └── 均为 🔴 TAINTED → 依赖于mbuf中的原始包大小信息
├── [L8901] appended_tail = MBUF_AppendMemorySpace_fl(mbuf, auth_and_tail_len, ...)
│   └── appended_tail 🔴 TAINTED → 指向mbuf追加的尾部空间
│       ├── [L8906] 填充pad_len个padding字节（使用循环计数器，clean）
│       └── [L8908] appended_tail[pad_len + 1] = *((uint8_t *)packet_info + 32)
│           └── ⚠️ DIRECT_SINK: packet_info[32]被写入ESP尾部的下一头字段
├── [L8948] chunk = MBUF_MakeMemoryContinuous_fl(mbuf, dbg_type, chunk_len, ...)
│   └── chunk 🔴 TAINTED → 指向mbuf中的负载数据
│       └── [L8951] block_ptr = (uint8_t *)chunk
│           └── block_ptr 🔴 TAINTED
│               ├── [L8953] enc_desc[24](sa_entry, block_ptr, chunk_len) ⚠️ DIRECT_SINK
│               ├── [L8955] auth_desc[7](auth_ctx, block_ptr, block_size) ⚠️ DIRECT_SINK
│               └── [L8969] memcpy_s(sa_entry+80, block_ptr, iv_len) ⚠️ DIRECT_SINK
├── [L9076] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, *packet_info, scratch_buf)
│   └── scratch_buf 🔴 TAINTED → 包含mbuf数据副本的新污点载体
│       ├── [L9088] MBUF_CopyDataFromBufferToMBuf(mbuf, 0, *packet_info, scratch_buf, ...) ⚠️ DIRECT_SINK
│       └── [L9092] MBUF_CopyDataFromBufferToMBuf(mbuf, *packet_info, iv_len+8, esp_hdr, ...)
├── [L9080] MBUF_PrependMemorySpace_fl(mbuf, iv_len + 8, ...) ⚠️ DIRECT_SINK
└── [L9112] MBUF_PrependMemorySpace_fl(mbuf, iv_len + 8, ...) ⚠️ DIRECT_SINK
```

### INPUT-2: parse_state/packet_info 🔴 TAINTED
```
parse_state/packet_info 🔴 TAINTED
├── [L8791] dbg_flow = __builtin_bswap32(packet_info[13])
│   └── dbg_flow 🔴 TAINTED → 目的IPv4，影响调试分支条件
├── [L8792] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...)
│   └── ⚠️ DIRECT_SINK: *packet_info（=parse_state[0..3]）控制mbuf内存读取大小
├── [L8827] RAW_U32(&algo_dbg_word, 0) = packet_info[3]; RAW_U16(&algo_dbg_word, 4) = 50
│   └── algo_dbg_word 🔴 TAINTED → 攻击者SPI + 50（协议号）注入调试关键字
│       └── [L8835] VOS_AVL3_Find(lib_ctx+120, &algo_dbg_word, ...)
│           └── ⚠️ DIRECT_SINK: 污点SPI作为AVL树查找关键字
├── [L8908] dbg_type = packet_info[14]
│   └── dbg_type 🔴 TAINTED → send_if_index（mbuf元数据）
├── [L8927] packet_size = packet_info[4]
│   └── packet_size 🔴 TAINTED → PST_TOTAL_LEN（从IP头解析）
│       ├── [L8928] payload_offset = packet_size - *packet_info → payload_offset 🔴 TAINTED
│       │   └── [L8929] packet_info[5] = payload_offset → 写回parse_state[20..23]
│       ├── [L8930] pad_len = (block_size - ((payload_offset + 2) % block_size)) % block_size
│       │   └── pad_len 🔴 TAINTED
│       │       ├── [L8906] 循环填充 appended_tail[offset]（循环计数器clean）
│       │       └── [L8908] appended_tail[pad_len + 1] = *((uint8_t *)packet_info + 32)
│       ├── [L8931] tail_len = pad_len + 2 → tail_len 🔴 TAINTED
│       ├── [L8932] packet_info[6] = iv_len + 8 + payload_offset + tail_len → 写回parse_state[24..27]
│       ├── [L8935] *((uint8_t *)packet_info + 29) = (uint8_t)tail_len → 写回parse_state[29]
│       ├── [L8937] *((uint8_t *)packet_info + 31) = block_size → 写回parse_state[31]
│       ├── [L8938] *((uint8_t *)packet_info + 32) = (uint8_t)tail_len → 写回parse_state[32]
│       └── [L8936] new_packet_size = packet_size + iv_len + 8 + auth_and_tail_len → new_packet_size 🔴 TAINTED
│           └── ⚠️ DIRECT_SINK: packet_size（网络解析值）参与整数溢出检查 > 0xFFFF
│       └── [L8951] RAW_U16((void *)ip_header, 2) = *((uint16_t *)packet_info + 5) + 8 + ...
│           └── ⚠️ DIRECT_SINK: parse_state[10..11]（PST_PACKET_LEN）被写入IP头总长度字段
├── [L8970] offset = RAW_U32((void *)sa_entry, 76)
│   └── [L8972] esp_hdr[0] = __builtin_bswap32(packet_info[3])
│       └── esp_hdr[0] 🔴 TAINTED → 攻击者SPI被写入ESP头字段
│           └── [L9118] MBUF_CopyDataFromBufferToMBuf(mbuf, *packet_info, iv_len+8, &esp_hdr[0], ...)
│               └── ⚠️ DIRECT_SINK: 含攻击者SPI的ESP头被写入mbuf传出包
├── [L8974] esp_iv[0] = __builtin_bswap32(offset) → esp_iv[0]（可信，SA序列号）
├── [L8976] esp_hdr[1] = __builtin_bswap32(RAW_U32((void *)sa_entry, 76))
│   └── esp_hdr[1] 🔴 TAINTED
├── [L9013] dbg_type = *packet_info
│   └── dbg_type 🔴 TAINTED → 覆盖为 parse_state[0..3]（PST_HDR_OFFSET），攻击者可控
│       └── [L8948] chunk = MBUF_MakeMemoryContinuous_fl(mbuf, dbg_type, chunk_len, ...)
│           └── ⚠️ DIRECT_SINK: dbg_type（污点）控制内存连续化的类型参数
├── [L9042] chunk_len = packet_info[6] - iv_len - 8 - auth_hash_len - offset
│   └── chunk_len 🔴 TAINTED → packet_info[6] 来自 parse_state[24..27]
│       └── [L8948] chunk = MBUF_MakeMemoryContinuous_fl(mbuf, dbg_type, chunk_len, ...)
│           └── ⚠️ DIRECT_SINK: chunk_len（污点）控制mbuf内存读取大小
├── [L9107] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, *packet_info, scratch_buf)
│   └── ⚠️ DIRECT_SINK: *packet_info（parse_state[0..3]）控制复制大小
│       scratch_buf 🔴 TAINTED → 从mbuf读入完整IP包数据，成为新污点载体
│           ├── [L9115] MBUF_CopyDataFromBufferToMBuf(mbuf, *packet_info, ..., scratch_buf, ...)
│           │   └── ⚠️ DIRECT_SINK: 污点scratch_buf被写回mbuf
│           └── [L9122] MBUF_CopyDataFromBufferToMBuf(mbuf, ..., esp_hdr, ...)
├── [L9112] MBUF_PrependMemorySpace_fl(mbuf, iv_len + 8, ...)
│   └── ⚠️ DIRECT_SINK: mbuf被修改以准备接收ESP头
├── [L9095/L9121] 条件判断: dbg_flow/SPI值驱动debug分支 → 间接影响控制流
└── [L8914/L9095/L9121/L9124] IPSEC_PKT_DebugPacketV4(..., dbg_flow, ...) 📎 见跟入列表
```

---

## 新导入的污点对象（输出参数写入）

| 变量名 | 派生来源 | 派生位置 | 说明 |
|--------|---------|---------|------|
| ip_header | MBUF_MakeMemoryContinuous_fl返回值 | L8792 | 指向mbuf中的IP头数据 |
| appended_tail | MBUF_AppendMemorySpace_fl返回值 | L8901 | 指向mbuf追加的尾部空间 |
| chunk | MBUF_MakeMemoryContinuous_fl返回值 | L8948 | 指向mbuf中的负载数据 |
| block_ptr | chunk派生 | L8951 | 用于遍历处理负载块 |
| scratch_buf | MBUF_CopyDataFromMBufToBuffer写入 | L9076/L9107 | 包含mbuf数据副本的新污点载体 |
| esp_hdr[0] | packet_info[3]赋值 | L8972 | 承载攻击者控制的SPI值 |
| esp_hdr[1] | sa_entry偏移76赋值 | L8976 | 承载序列号 |
| algo_dbg_word | packet_info[3]赋值 | L8827 | 攻击者SPI + 50注入调试关键字 |
| dbg_flow | packet_info[13]赋值 | L8791 | 承载目的IPv4 |
| dbg_type | packet_info[0]覆盖 | L9013 | 被解析的头偏移覆盖 |
| payload_offset | packet_info[4]派生 | L8928 | 负载偏移量 |
| pad_len | payload_offset派生 | L8930 | 填充长度 |
| tail_len | pad_len派生 | L8931 | 尾部长度 |
| new_packet_size | packet_size派生 | L8936 | 新数据包大小 |
| chunk_len | packet_info[6]派生 | L9042 | 分块处理长度 |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| packet_info[3] (esp_spi) | 写入 esp_hdr[0] | L8972 | 攻击者SPI写入所有传出ESP包的SPI字段 |
| packet_info[3] | 写入 algo_dbg_word | L8827 | 污点SPI作为SA查找关键字 |
| packet_info[4] (TOTAL_LEN) | 控制内存操作大小 | L8792, L9107 | 来自IP头解析的长度值驱动内存读取/复制 |
| packet_info[6] (payload+tail+iv) | 控制循环边界 chunk_len | L9042 | 派生长度控制处理负载数据量 |
| packet_info[32] (tail_len) | 写入 ESP trailer | L8938, L8908 | 攻击者控制的tail_len值写入ESP尾部 |
| *packet_info (HDR_OFFSET) | 控制 dbg_type/mbuf操作 | L8792, L9013, L9115 | 解析的头偏移控制内存操作参数 |
| packet_info[13] (DST4) | 控制 debug flow | L8791 | 攻击者IP影响调试分支 |
| algo_dbg_word | 写入 SADB AVL树查找 | L8835 | 污点SPI作为安全关联数据库查找关键字 |
| esp_hdr[0] | 写入 mbuf 传出包 | L9118 | 攻击者SPI被写入传出ESP头 |
| scratch_buf | 完整IP包数据 | L9107 | 由parse_state长度控制复制生成新污点载体 |
| new_packet_size | 整数溢出检查 | L8936 | 网络解析长度参与数据包大小安全检查 |
| ip_header | 写入IP头总长度字段 | L8951 | 解析长度注入IP头 |
| appended_tail | 写入ESP尾部 | L8908 | 污点数据直接写入包尾部 |
| chunk/block_ptr | 加密/认证处理 | L8953, L8955, L8969 | 污点负载数据被送入加密和认证函数 |

---

## 关键DIRECT_SINK汇总

| 位置 | 操作 | 危险 |
|------|------|------|
| L8792 | `MBUF_MakeMemoryContinuous_fl(..., *packet_info, ...)` | `*packet_info`（parse_state[0..3]）控制内存读取大小 |
| L8827 | `algo_dbg_word = packet_info[3]` | 攻击者SPI注入调试关键字 |
| L8835 | `VOS_AVL3_Find(..., &algo_dbg_word, ...)` | 污点SPI作为AVL树查找关键字 |
| L8908 | `appended_tail[pad_len+1] = packet_info[32]` | 污点tail_len被写入ESP尾部下一协议字段 |
| L8930 | `pad_len = ... payload_offset ...` | payload_offset驱动pad_len，影响尾部填充循环边界 |
| L8938 | `*(packet_info + 32) = tail_len` | 污点tail_len写回parse_state[32] |
| L8951 | `ip_header[2] = *((uint16_t *)packet_info + 5) + ...` | parse_state[10..11]被注入IP头总长度字段 |
| L8953 | `enc_desc[24](sa_entry, block_ptr, chunk_len)` | 污点负载数据被送入加密函数 |
| L8955 | `auth_desc[7](auth_ctx, block_ptr, block_size)` | 污点数据影响HMAC认证计算 |
| L8969 | `memcpy_s(sa_entry+80, 16, block_ptr, iv_len)` | 最后密文块污染SA的IV状态 |
| L8972 | `esp_hdr[0] = packet_info[3]` | 攻击者SPI被写入ESP头SPI字段 |
| L9013 | `dbg_type = *packet_info` | parse_state[0..3]覆盖dbg_type，后续控制内存操作 |
| L9042 | `chunk_len = packet_info[6] - ...` | packet_info[6]控制循环边界 |
| L9076 | `MBUF_CopyDataFromMBufToBuffer(..., *packet_info, ...)` | 复制大小由parse_state控制 |
| L9088 | `MBUF_CopyDataFromBufferToMBuf(mbuf, scratch_buf)` | 污点scratch_buf被写回mbuf |
| L9107 | `MBUF_CopyDataFromMBufToBuffer(mbuf, scratch_buf)` | 新污点载体scratch_buf |
| L9115 | `MBUF_CopyDataFromBufferToMBuf(mbuf, *packet_info, ..., scratch_buf, ...)` | 偏移受控，scratch_buf含完整IP包 |
| L9118 | `MBUF_CopyDataFromBufferToMBuf(mbuf, ..., &esp_hdr[0], ...)` | 含攻击者SPI的ESP头被写入mbuf传出包 |
| L9080 | `MBUF_PrependMemorySpace_fl(mbuf, iv_len+8)` | mbuf被修改以接收ESP头 |
| L9112 | `MBUF_PrependMemorySpace_fl(mbuf, iv_len+8)` | mbuf被修改以准备接收ESP头 |