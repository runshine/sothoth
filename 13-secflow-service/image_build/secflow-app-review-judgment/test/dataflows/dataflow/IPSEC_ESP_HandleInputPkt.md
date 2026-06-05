## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_ESP_HandleInputPkt

## 函数信息
- 文件: libipsec.c
- 签名: `IPSEC_ESP_HandleInputPkt`

## 污点源
- **mbuf** 🔴 TAINTED — 外部网络输入,ESP加密数据包

## 污点传播路径

### INPUT-1: mbuf 🔴 TAINTED
```
├── [L9392] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...)
│   └── ip_header 🔴 TAINTED (IP头视图)
│       └── [L3686] ip_header[1] = next_header (外层IP头协议号) → 📌 USED
├── [L9409] esp_header = MBUF_MakeMemoryContinuous_fl(mbuf, *packet_info, 24, ...)
│   └── esp_header 🔴 TAINTED (ESP头视图)
│       └── [L9438] esp_header[0] → sa_lookup_key 🔴 TAINTED
│           └── [L9446] VOS_AVL3_Find(..., &sa_lookup_key, ...) — SA查找
├── [L9501] MBUF_CopyDataFromMBufToBuffer(mbuf, ..., received_auth)
│   └── 复制认证标签到 received_auth (本地变量)
├── [L9535] chunk = MBUF_MakeMemoryContinuous_fl(mbuf, chunk_offset, chunk_len, ...)
│   └── chunk 🔴 TAINTED (认证区域分片视图)
│       └── [L9564] AUTH_UPDATE(..., chunk, chunk_len)
├── [L9670] MBUF_CopyDataFromMBufToBuffer(mbuf, ..., esp_tail_block)
│   └── esp_tail_block 🔴 TAINTED (加密尾部数据) ← 【新引入污点对象】
│       ├── [L9685] pad_length = esp_tail_block[enc_block_size - 2] 🔴 TAINTED
│       ├── [L9686] next_header = esp_tail_block[enc_block_size - 1] 🔴 TAINTED
│       ├── [L9688] packet_info[29] = pad_length
│       ├── [L9689] packet_info[32] = next_header
│       └── ⚠️ DIRECT_SINK: MBUF_CutTail_fl(mbuf, pad_length+2+auth_hash_len, ...)
│           └── 切割大小参数来源于 esp_tail_block
└── [L9677] IPSEC_ESP_Decryption(mbuf, packet_info, sa_entry, tail_block_ref)
    └── mbuf (解密后) 🔴 TAINTED (原位解密) ← 【新引入污点对象】
        ├── [L9706] MBUF_CutTail_fl(mbuf, ...)
        ├── [L9719] MBUF_CutPart_fl(mbuf, ...)
        ├── [L9741] MBUF_CreateControlInfo_fl(mbuf, ...)
        └── [L9745] MBUF_GetControlInfo(mbuf, ...)
```

### INPUT-2: esp_tail_block 🔴 TAINTED (新引入)
```
├── [L9685] pad_length = esp_tail_block[enc_block_size - 2] 🔴 TAINTED
│   └── ⚠️ DIRECT_SINK: 数组下标依赖 enc_block_size 偏移量
├── [L9686] next_header = esp_tail_block[enc_block_size - 1] 🔴 TAINTED
├── [L9688] packet_info[29] = pad_length
├── [L9689] packet_info[32] = next_header
└── ⚠️ DIRECT_SINK: MBUF_CutTail_fl(mbuf, pad_length+2+auth_hash_len, ...)
    └── 切割大小参数受 esp_tail_block 控制
```

### INPUT-3: mbuf (解密后) 🔴 TAINTED (新引入)
```
├── [L9706] MBUF_CutTail_fl(mbuf, ...) → 去除解密尾部
├── [L9719] MBUF_CutPart_fl(mbuf, ...) → 去除ESP头部
├── [L9741] MBUF_CreateControlInfo_fl(mbuf, ...) → 创建控制信息
└── [L9745] MBUF_GetControlInfo(mbuf, ...) → 提取控制信息
```

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf | ip_header[1]=next_header | L3686 | 外层IP头协议号写入 |
| mbuf | MBUF_CutTail_fl (切割大小) | L9685附近 | pad_length参数受esp_tail_block控制 |
| esp_tail_block | 数组访问 | L9685-9686 | 污点数据作为数组下标偏移 |
| mbuf (解密后) | MBUF_CutTail_fl | L9706 | 去除解密尾部 |
| mbuf (解密后) | MBUF_CutPart_fl | L9719 | 去除ESP头部 |
| mbuf (解密后) | MBUF_CreateControlInfo_fl | L9741 | 创建控制信息 |
| mbuf (解密后) | MBUF_GetControlInfo | L9745 | 提取控制信息 |

## 特殊标记
- ⚠️ DIRECT_SINK: MBUF_CutTail_fl 的切割大小参数来自 esp_tail_block，pad_length 由污点数据控制
- ⚠️ DIRECT_SINK: esp_tail_block[enc_block_size-2/1] 数组下标依赖固定偏移，可能越界