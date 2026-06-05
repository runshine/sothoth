## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `lib_ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `packet_info` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `stats_ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_ESP_HandleInputPktV4

## 函数信息
- 文件: libipsec.c
- 签名: `void IPSEC_ESP_HandleInputPktV4(void *mbuf, unsigned int *packet_info, int64_t lib_ctx, int64_t stats_ctx)`

---

## 污点源 (4个)

| ID | 变量 | 类型 | 来源 | 说明 |
|----|------|------|------|------|
| INPUT-1 | mbuf | void* | 外部网络输入 | 承载 ESP 加密数据包 |
| INPUT-2 | packet_info | unsigned int* | 外部网络输入 | 包信息数组指针，来自解析输出 |
| INPUT-3 | lib_ctx | int64_t | 外部上下文句柄 | 安全库上下文 |
| INPUT-4 | stats_ctx | int64_t | 外部输入参数 | 统计上下文句柄 |

---

## 新导入的污点载体 (由输出参数/读取操作产生)

| 变量 | 类型 | 产生位置 | 来源 | 说明 |
|------|------|---------|------|------|
| ip_header | uint8_t* | L9821, L9829 | MBUF_MakeMemoryContinuous_fl | 从 mbuf 提取 IP 头 |
| esp_header | uint32_t* | L9830, L9842 | MBUF_MakeMemoryContinuous_fl | 从 mbuf 提取 ESP 头 |
| sa_lookup_key | uint32_t | L9859 | esp_header 字节序转换 | 用于 SA 查找 |
| dbg_flow_id | uint32_t | L9840 | packet_info[13] | 调试流 ID |
| authenticated_len | uint32_t | L1084 | packet_info[6] | 认证数据长度 |
| chunk_offset | uint32_t | L1097 | *packet_info | 分块偏移量 |
| received_auth | uint8_t[64] | L1082, L1093 | MBUF_CopyDataFromMBufToBuffer | mbuf 认证数据拷贝 |
| chunk | void* | L1095, L1104 | MBUF_MakeMemoryContinuous_fl | 加密有效载荷分块 |
| esp_tail_block | uint8_t[16] | L1159, L1161 | MBUF_CopyDataFromMBufToBuffer | ESP 尾部数据 |
| pad_length | uint8_t | L1191, L1194 | esp_tail_block[pad_index] | ESP 填充长度 |
| next_protocol | uint8_t | L1192, L1195 | esp_tail_block[pad_index+1] | 下一层协议 |

---

## 完整数据流树状图

### INPUT-1: mbuf (void*) 🔴 TAINTED
```
├── [L9821] MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...) → ip_header 🔴 TAINTED
│   └── [L9834] ip_header_words = ip_header[0] & 0xF → 边界控制
├── [L9829] MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...) → ip_header 🔴 TAINTED
├── [L9830] MBUF_MakeMemoryContinuous_fl(mbuf, *packet_info, 24, ...) → esp_header 🔴 TAINTED
│   └── [L9859] sa_lookup_key = __builtin_bswap32(*esp_header) → sa_lookup_key 🔴 TAINTED
│       └── [L9879] VOS_AVL3_Find(lib_ctx+120, &sa_lookup_key, ...) → 📎 子函数
├── [L9842] MBUF_MakeMemoryContinuous_fl(mbuf, *packet_info, 24, ...) → esp_header 🔴 TAINTED
│   └── [L9875] IPSEC_LIB_Ipv4AddrToStr(RAW_U32(ip_header,12), ...) → 调试输出
├── [L1082] MBUF_CopyDataFromMBufToBuffer(mbuf, packet_len-auth_hash_len, auth_hash_len, received_auth) → received_auth 🔴 TAINTED
├── [L1093] MBUF_CopyDataFromMBufToBuffer(mbuf, packet_len-auth_hash_len, auth_hash_len, received_auth) → received_auth 🔴 TAINTED
├── [L1095] MBUF_MakeMemoryContinuous_fl(mbuf, chunk_offset, chunk_len, ...) → chunk 🔴 TAINTED
├── [L1104] MBUF_MakeMemoryContinuous_fl(mbuf, chunk_offset, chunk_len, ...) → chunk 🔴 TAINTED
│   └── [L1113] AUTH_UPDATE(auth_desc, ..., chunk, chunk_len) → 🟡 EXPORT (标准加密库)
├── [L1153] MBUF_MakeMemoryContinuous_fl(mbuf, chunk_offset, enc_block_size, ...) → esp_tail_block 🔴 TAINTED
├── [L1159] MBUF_CopyDataFromMBufToBuffer(..., packet_len-enc_block_size-auth_hash_len, enc_block_size, esp_tail_block) → esp_tail_block 🔴 TAINTED
├── [L1161] MBUF_CopyDataFromMBufToBuffer(..., packet_len-enc_block_size-auth_hash_len, enc_block_size, esp_tail_block) → esp_tail_block 🔴 TAINTED
│   └── [L1168] IPSEC_ESP_Decryption(lib_ctx, mbuf, packet_info, ...) → 📎 子函数 (mbuf 进入解密)
├── [L1168] IPSEC_ESP_Decryption(lib_ctx, mbuf, packet_info, ...) → 📎 子函数
├── [L1237] MBUF_CheckSum(mbuf, ...) → 校验和计算 ⚠️ DIRECT_SINK
├── [L1245] MBUF_CutTail_fl(mbuf, pad_length+2+auth_hash_len, ...) → ⚠️ DIRECT_SINK: 截断大小受污点控制
│   └── [L1252] MBUF_CutPart_fl(mbuf, *packet_info, ...) → 📎 子函数
│       ├── [L1273] MBUF_CreateControlInfo_fl(mbuf, 10, 8, ...) → 📎 子函数
│       ├── [L1282] MBUF_SetFlag(mbuf, 0x10000000) → 📎 子函数
│       └── [L1284] MBUF_GetControlInfo(mbuf, 10) → 📎 子函数
└── [L1282] MBUF_SetFlag(mbuf, 0x10000000) → mbuf 标志设置
```

### INPUT-2: packet_info (unsigned int*) 🔴 TAINTED
```
├── [L9810] packet_info == NULL 验证检查 → 终止
├── [L9821] MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...) → ip_header 🔴 TAINTED
├── [L9830] MBUF_MakeMemoryContinuous_fl(mbuf, *packet_info, 24, ...) → esp_header 🔴 TAINTED
├── [L9840] dbg_flow_id = __builtin_bswap32(packet_info[13]) → dbg_flow_id 🔴 TAINTED
├── [L1028] packet_info[14] → RAW_U32(&algo_dbg_word, 0)
│   └── [L1030] IPSECL_DBG_EspPktAlgoV4(..., dbg_flow_id, ...) → 📎 子函数
├── [L1046] packet_len = packet_info[4] → packet_len 🔴 TAINTED
├── [L1048] *packet_info (offset) 用于 payload 长度验证
├── [L1053] packet_info[5] = payload_len → 写入
├── [L1056] packet_info[6] = SA_tail_size + 8 + payload_len → 写入
├── [L1084] authenticated_len = packet_info[6] → authenticated_len 🔴 TAINTED
├── [L1093] MBUF_CopyDataFromMBufToBuffer(..., packet_len-auth_hash_len, ...) → received_auth[] 🔴 TAINTED
├── [L1097] chunk_offset = *packet_info → chunk_offset 🔴 TAINTED
├── [L1104] MBUF_MakeMemoryContinuous_fl(mbuf, chunk_offset, chunk_len, ...) → chunk 🔴 TAINTED
│   └── [L1113] AUTH_UPDATE(auth_desc, ..., chunk, chunk_len) → 📎 子函数
├── [L1159] MBUF_CopyDataFromMBufToBuffer(..., packet_len-enc_block_size-auth_hash_len, ...) → esp_tail_block[] 🔴 TAINTED
├── [L1166] IPSEC_ESP_Decryption(lib_ctx, mbuf, packet_info, ...) → 📎 子函数 (packet_info 作为输出参数)
├── [L1193] pad_index = enc_block_size - 2
│   └── [L1194] pad_length = esp_tail_block[pad_index] → pad_length 🔴 TAINTED
│       └── [L1195] next_protocol = esp_tail_block[pad_index+1] → next_protocol 🔴 TAINTED
├── [L1196] *((uint8_t*)packet_info+29) = pad_length → 写入（来自 tainted esp_tail_block）
├── [L1197] *((uint8_t*)packet_info+32) = next_protocol → 写入（来自 tainted next_protocol）
├── [L1199] *packet_info 用于尾部长度边界验证
├── [L1216] ⚠️ DIRECT_SINK: ip_header[packet_info[1]] = esp_tail_block[pad_index+1] → packet_info[1] 作为数组下标
├── [L1218] ⚠️ DIRECT_SINK: ip_header[packet_info[1]] = next_protocol → 同上
├── [L1220] ip_header[9] = next_protocol → 🟢 CLEANED（固定索引9，非packet_info[1]）
├── [L1225] *((uint16_t*)packet_info+5) 用于 total_len 计算
├── [L1237] MBUF_CutTail_fl(mbuf, pad_length+2+auth_hash_len, ...) → pad_length 🔴 TAINTED
└── [L1248] MBUF_CutPart_fl(mbuf, *packet_info, ...) → *packet_info 🔴 TAINTED
```

### INPUT-3: lib_ctx (int64_t) 🔴 TAINTED
```
├── [L9810] lib_ctx == 0 验证检查 → 终止
├── [L9820] MBUF_MakeMemoryContinuous_fl(..., RAW_U64(lib_ctx,16), ...) → 📎 子函数
│   └── [L9841] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L9863] MBUF_MakeMemoryContinuous_fl(..., RAW_U64(lib_ctx,16), ...) → 📎 子函数
│   └── [L9870] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L9873] dbg_mode = RAW_U8(lib_ctx,400) → 控制流分支
│   └── [L9875] IPSEC_LIB_Ipv4AddrToStr(..., (int64_t)lib_ctx) → 📎 子函数
│   └── [L9876] IPSEC_LIB_Ipv4AddrToStr(..., (int64_t)lib_ctx) → 📎 子函数
├── [L1003] VOS_AVL3_Find(lib_ctx+120, ...) → 📎 子函数
│   └── [L1003] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1021] VOS_AVL3_Find(lib_ctx+76, ...) → 📎 子函数
│   └── [L1025-1027] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1035] IPSECL_DBG_EspPktAlgoV4(lib_ctx, ...) → 📎 子函数
├── [L1053] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1069] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1085] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1103] MBUF_MakeMemoryContinuous_fl(..., RAW_U64(lib_ctx,16), ...) → 📎 子函数
│   └── [L1110] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1115] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L1118] SSP_Debug(RAW_U32(lib_ctx,408), ..., RAW_U64(lib_ctx,440), ..., lib_ctx+448) → ⚠️ DIRECT_SINK: lib_ctx用作内存基址(偏移408,440,448)
├── [L1123] AUTH_FINAL(auth_desc, computed_auth, ..., lib_ctx, 64) → 📎 子函数
├── [L1127] RAW_U8(lib_ctx,403) → 控制流分支
│   └── [L1129] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
├── [L1130] IPSEC_PKT_DebugPacketV4(lib_ctx, ...) → 📎 子函数
├── [L1136] AUTH_FINAL(auth_desc, computed_auth, ..., lib_ctx, 64) → 📎 子函数
├── [L1139] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L1140] AUTH_FINAL(auth_desc, computed_auth, ..., lib_ctx, 64) → 📎 子函数
├── [L1145] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1146] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L1148] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
├── [L1155] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1157] IPSEC_ESP_Decryption(lib_ctx, ...) → 📎 子函数
├── [L1167] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1169] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L1171] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
├── [L1173] RAW_U8(lib_ctx,403) → 控制流分支
│   └── [L1174] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
├── [L1178] IPSEC_PKT_DebugPacketV4(lib_ctx, ...) → 📎 子函数
├── [L1185] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1195] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1204] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L1205] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1213] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L1215] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
├── [L1218] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
├── [L1234] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1241] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1248] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1261] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1263] MBUF_CreateControlInfo_fl(..., RAW_U64(lib_ctx,16), ...) → 📎 子函数
├── [L1269] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1285] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L1288] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
├── [L1290] IPSEC_PKT_DebugPacketV4(lib_ctx, ...) → 📎 子函数
└── [L1291] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
```

### INPUT-4: stats_ctx (int64_t) 🔴 TAINTED
```
├── [L9789] if (... stats_ctx == 0) → 🟢 CLEANED（空指针检查，不参与数据处理）
├── [L9846] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, 0, 28, 0) → 📎 子函数
├── [L9924] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 4, 0) → 📎 子函数
├── [L10035] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 6, 0) → 📎 子函数
├── [L10047] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 8, 0) → 📎 子函数
├── [L10061] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10113] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10133] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10147] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10159] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10174] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 8, 0) → 📎 子函数
├── [L10186] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 8, 0) → 📎 子函数
├── [L10207] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 8, 0) → 📎 子函数
├── [L10238] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 6, 0) → 📎 子函数
├── [L10251] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 6, 0) → 📎 子函数
├── [L10257] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 24, 0) → 📎 子函数
├── [L10263] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10276] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10290] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10303] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 21, ...) → 📎 子函数
└── [L10315] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
```

---

## 关键 DIRECT_SINK 汇总

| 位置 | 危险操作 | 说明 |
|------|---------|------|
| L1118 | SSP_Debug(RAW_U32(lib_ctx,408), ..., RAW_U64(lib_ctx,440), ..., lib_ctx+448) | lib_ctx 作为内存基址，攻击者可控制调试输出；若被污染，可读取任意地址+448 |
| L1129, L1148, L1171, L1174, L1215, L1218, L1288, L1291 | SSP_Debug(..., (const char*)(lib_ctx+448)) | lib_ctx+448 作为字符串指针，可导致任意地址读取 |
| L1216 | ip_header[packet_info[1]] = esp_tail_block[pad_index+1] | packet_info[1] 作为数组下标受污点影响，可越界写入 IP 头 |
| L1218 | ip_header[packet_info[1]] = next_protocol | 同上 |
| L1222 | new_total_len = (uint16_t)(...) | pad_length 参与 uint32→uint16 截断，可能丢失高字节 |
| L1237 | MBUF_CheckSum(mbuf, ...) | mbuf 用于校验和计算 |
| L1245 | MBUF_CutTail_fl(mbuf, pad_length+2+auth_hash_len, ...) | mbuf 截断大小由污点 pad_length 决定 |
| L1196 | *((uint8_t*)packet_info+29) = pad_length | 将污点数据写入输出参数 packet_info |
| L1197 | *((uint8_t*)packet_info+32) = next_protocol | 将污点数据写入输出参数 packet_info |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf | 📎 子函数 | 多处 | 作为包缓冲区传递给多个 MBUF 函数处理 |
| packet_info | 📎 子函数 | 多处 | 作为包信息参数传递给解密和调试函数 |
| lib_ctx | ⚠️ DIRECT_SINK | L1118, L1129, L1148, L1171, L1174, L1215, L1218, L1288, L1291 | 作为内存基址用于调试输出 |
| stats_ctx | 📎 子函数 | 21处 | 作为句柄传递给统计更新函数 |
| ip_header | ⚠️ DIRECT_SINK | L1216, L1218 | 作为污点下标写入目标 |
| pad_length | ⚠️ DIRECT_SINK | L1245 | 作为截断长度参数 |
| esp_tail_block | *((uint8_t*)packet_info+...) | L1196, L1197 | 数据写入输出参数 |