## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `ip_header` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIB_Ipv6AddrToStr

## 函数信息
- 文件: libipsec.c
- 行号: L7658-L7677
- 签名: `void IPSEC_LIB_Ipv6AddrToStr(void *addr_ptr, char *out_str)`

## 污点源 (继承自调用上下文)
- addr_ptr (void*) 🔴 TAINTED — 继承自 ip_header 外部网络数据包缓冲区指针
  - 调用点1: L5263 传入 `ip_header + 8` (IPv6 源地址字段)
  - 调用点2: L5264 传入 `ip_header + 24` (IPv6 目的地址字段)

## 传播路径

### addr_ptr 🔴 TAINTED (外部输入)
├── [L7673] memcpy_s(addr_words, 16, (const void *)addr_ptr, 16)
│   ⚠️ DIRECT_SINK: 从 ip_header+8 或 ip_header+24 读取 16 字节，源地址受污点控制
│   └── [L7675] addr_words[i] = __builtin_bswap16(addr_words[i])
│       └── addr_words[] 仍 🔴 TAINTED (字节序交换后污点仍保留)
│           └── [L7676] VOS_Inet_ntoa_b_ipv6(addr_words[0], addr_words[1], (char *)out_str)
│               📎 子函数: VOS_Inet_ntoa_b_ipv6
└── [L7676] 📌 USED (VOS_Inet_ntoa_b_ipv6 消费污点 addr_words)

## 数据流树状图

```
### INPUT: addr_ptr (void*) 🔴 TAINTED (继承自外部网络输入 ip_header)
├── [L5263] 调用点: ip_header+8 (IPv6源地址) → addr_ptr 🔴 TAINTED
├── [L5264] 调用点: ip_header+24 (IPv6目的地址) → addr_ptr 🔴 TAINTED
└── [L7673-L7676] 内部处理
    └── [L7673] memcpy_s 从污点指针读取 16 字节
        ⚠️ DIRECT_SINK: 指针偏移受 ip_header 污点控制
        └── [L7675] 字节序交换 → addr_words[] 仍 🔴 TAINTED
            └── [L7676] VOS_Inet_ntoa_b_ipv6(addr_words, out_str) → 📌 USED
```

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| addr_ptr | VOS_Inet_ntoa_b_ipv6 | L7676 | 16字节IPv6地址写入输出字符串 |
| addr_words[] | VOS_Inet_ntoa_b_ipv6 | L7676 | 字节序转换后仍为污点 |

## 新导入的污点对象
- **addr_words[16]** (uint16_t[16]): memcpy_s 从污点指针 addr_ptr 复制 16 字节后成为污点载体，在函数内部继续传播

## 安全摘要
⚠️ **核心风险**: addr_ptr 继承自外部网络数据包缓冲区 ip_header，偏移量 +8/+24 对应 IPv6 源/目的地址（网络输入完全可控）
- L7673: memcpy_s 从污点指针读取 16 字节到栈缓冲区 addr_words，指针偏移受污点控制
- L7675: __builtin_bswap16 字节序交换后污点状态仍保留
- L7676: 转换后的 IPv6 字符串写入 out_str，out_str 由调用者分配（65字节缓冲区）