## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_AH_HandleInputPkt

## 函数信息
- 文件: libipsec.c
- 函数: IPSEC_AH_HandleInputPkt
- 污点源: mbuf_base (外部网络mbuf数据包缓冲区)

## 污点源
- `mbuf_base` (int64_t) 🔴 TAINTED — 外部网络mbuf数据包缓冲区

## 传播路径

### mbuf_base 🔴 TAINTED (外部网络输入)
```
├── [L5638] packet_copy = MBUF_CopyDataFromMBufToBuffer(mbuf_base, 0, packet_info[0], packet_copy)
│   ├── [L5653] first_byte = *(uint8_t*)packet_copy
│   └── [L5660-5662] 算法处理packet_copy
│
├── [L5682] 循环处理payload chunks
│   ├── [L5682] chunk_base = MBUF_MakeMemoryContinuous_fl(mbuf_base, copy_offset, chunk_len, ...)
│   │   └── [L5719] memcpy_s((uint8_t*)payload_copy+copied_len, chunk_len, chunk_base, chunk_len) ⚠️ DIRECT_SINK
│   └── [L5726] payload_copy 累积污点数据 🔴 TAINTED (新导入对象)
│
├── [L5698] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf_base, 0, packet_info[0], ...) 🔴 TAINTED (新导入对象)
│   ├── [L5684] RAW_U8((void*)ip_header, packet_info[1]) = ah_header[0] ⚠️ DIRECT_SINK (污点偏移写入)
│   └── [L5758] 修改协议字段
│
├── [L5710] ah_header = MBUF_MakeMemoryContinuous_fl(mbuf_base, packet_info[0], packet_info[4]-packet_info[0], ...) 🔴 TAINTED (新导入对象)
│   ├── [L5712] ah_spi_network = __builtin_bswap32(*(uint32_t*)(ah_header+4))
│   ├── [L5714] sa_lookup_key = ah_spi_network
│   ├── [L5716] sa_entry = VOS_AVL3_Find(..., &sa_lookup_key, ...) 📎 见跟入列表
│   ├── [L5729] next_header = ah_header[0]
│   └── [L5736] VOS_MemCmp(computed_auth, ah_header+12, auth_hash_len) 📎 见跟入列表
│
├── [L5764] MBUF_CutPart_fl(mbuf_base, packet_info[0], auth_hash_len+12, ...)
├── [L5775] MBUF_CreateControlInfo_fl(mbuf_base, 10, 8, ...)
├── [L5789] MBUF_GetControlInfo(mbuf_base, 10)
└── [L5791] MBUF_SetFlag(mbuf_base, 0x10000000)
```

## 新导入的污点对象 (在函数内从mbuf导出)
| 对象名 | 类型 | 导入方式 | 位置 |
|--------|------|----------|------|
| ip_header | void* | MBUF_MakeMemoryContinuous_fl(mbuf_base, ...) | L5698 |
| ah_header | void* | MBUF_MakeMemoryContinuous_fl(mbuf_base, ...) | L5710 |
| packet_copy | void* | MBUF_CopyDataFromMBufToBuffer(mbuf_base, ...) | L5638 |
| chunk_base | void* | MBUF_MakeMemoryContinuous_fl(mbuf_base, ...) | L5682 |
| payload_copy | void* | 循环中memcpy_s累积写入 | L5726 |
| ah_spi_network | uint32_t | 从ah_header+4提取 | L5712 |
| sa_lookup_key | uint32_t | 从ah_spi_network赋值 | L5714 |

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf_base | MBUF_CopyDataFromMBufToBuffer | L5638 | 提取packet数据 |
| mbuf_base | MBUF_MakeMemoryContinuous_fl | L5682 | 循环提取payload chunks |
| mbuf_base | MBUF_MakeMemoryContinuous_fl | L5698 | 提取IP头 |
| mbuf_base | MBUF_MakeMemoryContinuous_fl | L5710 | 提取AH头 |
| mbuf_base | MBUF_CutPart_fl | L5764 | 裁剪数据包 |
| chunk_base/payload_copy | memcpy_s | L5719 | ⚠️ DIRECT_SINK: 复制大小由污点控制 |
| ip_header/packet_info[1] | RAW_U8写入 | L5684 | ⚠️ DIRECT_SINK: 写入偏移由污点控制 |
| ah_header+12 | VOS_MemCmp | L5736 | 验证认证数据 |
| ah_spi_network | VOS_AVL3_Find | L5716 | SA查找 |

## 高危操作 (DIRECT_SINK)
- **L5719**: `memcpy_s((uint8_t*)payload_copy+copied_len, chunk_len, chunk_base, chunk_len)` 
  - 污点指针chunk_base和大小chunk_len控制复制操作
- **L5684**: `RAW_U8((void*)ip_header, packet_info[1]) = ah_header[0]` 
  - 污点偏移packet_info[1]用于写入IP头字段