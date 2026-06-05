## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `addr_words` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: __builtin_bswap16

## 函数信息
- 文件: libipsec.c
- 调用位置: L7671 (循环内)
- 签名: `uint16_t __builtin_bswap16(uint16_t)`

## 污点源
- addr_words 🔴 TAINTED — 从外部 addr_ptr 经 memcpy_s 导入网络数据 (L7670)

## 数据流树状图

### INPUT-1: ((uint16_t*)addr_words)[i] (uint16_t&) 🔴 TAINTED
├── [L7671] ret = __builtin_bswap16(((uint16_t*)addr_words)[i]) → ret 🔴 TAINTED
│   └── ⚠️ DIRECT_SINK: 编译器builtin对tainted buffer进行字节交换
├── [L7671] ((uint16_t*)addr_words)[i] = ret → addr_words[i] 🔴 TAINTED
│   └── 🟢 回写操作，标记为sink但不影响污点状态
└── [L7672] VOS_Inet_ntoa_b_ipv6(addr_words[0], addr_words[1], out_str) → 📌 USED

### INPUT-2: addr_words[0] (uint64_t) 🔴 TAINTED
└── [L7672] VOS_Inet_ntoa_b_ipv6(addr_words[0], addr_words[1], out_str) → 📌 USED

### INPUT-3: addr_words[1] (uint64_t) 🔴 TAINTED
└── [L7672] VOS_Inet_ntoa_b_ipv6(addr_words[0], addr_words[1], out_str) → 📌 USED

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| ((uint16_t*)addr_words)[i] | __builtin_bswap16 | L7671 | 编译器builtin字节交换处理 |
| addr_words[0], addr_words[1] | VOS_Inet_ntoa_b_ipv6 | L7672 | 作为IPv6地址输出参数 |