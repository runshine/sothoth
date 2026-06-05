## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: RAW_U64

## 函数信息
- 文件: libipsec.c
- 功能: 从 parse_state 缓冲区提取 64 位数据
- 签名: `uint64_t RAW_U64(uint8_t *parse_state, uint8_t offset)`

## 污点传播分析

### 输入参数
| 参数 | 类型 | 污点状态 | 来源 |
|------|------|----------|------|
| `parse_state` | uint8_t* | 🔴 TAINTED | 由 IPSEC_PKT_ParseAndVerifyHdr() 从网络 mbuf 填充 |
| `offset` | uint8_t | 🟢 CLEAN | 编译时常量 PST_DST6 + 0/8 |

### RAW_U64 函数行为
```
RAW_U64(parse_state, offset)
├── 从 parse_state[offset] 开始读取 8 字节
├── 组装为 uint64_t 返回值
└── 返回值 🔴 TAINTED (直接从污点缓冲区提取)
```

### 数据流树状图

#### INPUT-1: parse_state (uint8_t*) 🔴 TAINTED
```
parse_state 🔴 TAINTED [缓冲区来自外部网络数据]
│
├── [L10852] dst_filter_lo = RAW_U64(parse_state, PST_DST6 + 0)
│   └── dst_filter_lo 🔴 TAINTED
│       └── 用途: IPv6 地址低 64 位 (目标地址过滤)
│
├── [L10853] dst_filter_hi = RAW_U64(parse_state, PST_DST6 + 8)
│   └── dst_filter_hi 🔴 TAINTED
│       └── 用途: IPv6 地址高 64 位 (目标地址过滤)
│
├── [L11050] dst_filter_lo = RAW_U64(parse_state, PST_DST6 + 0)
│   └── dst_filter_lo 🔴 TAINTED (输入处理路径)
│
└── [L11051] dst_filter_hi = RAW_U64(parse_state, PST_DST6 + 8)
    └── dst_filter_hi 🔴 TAINTED (输入处理路径)
```

### RAW_U64 返回值安全分析

| 调用位置 | 偏移常量 | 缓冲区范围 | 状态 |
|----------|----------|------------|------|
| L10852, L11050 | PST_DST6 + 0 = 36 | parse_state[36-43] | ✅ 安全 |
| L10853, L11051 | PST_DST6 + 8 = 44 | parse_state[44-51] | ✅ 安全 |

- 偏移量 `PST_DST6 = 36` 为编译时常量，非攻击者可控
- 无缓冲区越界风险
- 无 DIRECT_SINK 风险

### 新导入的污点对象（RAW_U64 产生）

| 对象 | 类型 | 污点来源 | 用途 |
|------|------|----------|------|
| `dst_filter_lo` | uint64_t | RAW_U64(parse_state, PST_DST6+0) | IPv6 目标地址低 64 位过滤 |
| `dst_filter_hi` | uint64_t | RAW_U64(parse_state, PST_DST6+8) | IPv6 目标地址高 64 位过滤 |

### 接收此污点的子函数

| 函数 | 调用位置 | 接收的形参 |
|------|---------|------------|
| `IPSEC_PKT_ParseAndVerifyHdr` | L10832, L11030 | `packet_state` — 填充后成为污点载体 |
| `IPSEC_LIBI_GetManualSa` | L10855, L11053 | `manual_sa_cfg` — 使用网络派生的SPI/目的IP查找SA |
| `IPSEC_AH_HandleOutputPkt` | L10868 | `packet_info` — 使用网络派生的SPI/目的/协议处理输出 |
| `IPSEC_ESP_HandleOutputPkt` | L10897 | `packet_info` — 使用网络派生的SPI/目的/协议处理输出 |
| `IPSEC_AH_HandleInputPkt` | L11062 | `packet_info` — 使用网络头部字段处理输入 |
| `IPSEC_ESP_HandleInputPkt` | L11085 | `packet_info` — 使用网络头部字段处理输入 |

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| parse_state | IPSEC_PKT_ParseAndVerifyHdr | L10832, L11030 | 解析后成为完整污点载体 |
| parse_state | IPSEC_LIBI_GetManualSa | L10855, L11053 | 使用网络派生的SPI/目的IP |
| parse_state | IPSEC_AH_HandleOutputPkt | L10868 | 使用网络头部字段处理输出 |
| parse_state | IPSEC_ESP_HandleOutputPkt | L10897 | 使用网络头部字段处理输出 |
| parse_state | IPSEC_AH_HandleInputPkt | L11062 | 使用网络头部字段处理输入 |
| parse_state | IPSEC_ESP_HandleInputPkt | L11085 | 使用网络头部字段处理输入 |
| RAW_U64 返回值 | dst_filter_lo | L10852, L11050 | 目标IPv6地址低64位 |
| RAW_U64 返回值 | dst_filter_hi | L10853, L11051 | 目标IPv6地址高64位 |