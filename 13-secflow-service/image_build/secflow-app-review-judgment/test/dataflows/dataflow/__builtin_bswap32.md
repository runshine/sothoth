## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: __builtin_bswap32

## 函数信息
- 文件: libipsec.c
- 行号: (compiler builtin)
- 签名: `uint32_t __builtin_bswap32(uint32_t x)`

## 数据流树状图

### INPUT-1: x (uint32_t) 🔴 TAINTED
├── [L11628] `dst_ipv4 = __builtin_bswap32(RAW_U32(parse_state, 52))`
│   └── dst_ipv4 🔴 TAINTED
│       ├── [L11640] `IPSEC_PKT_DebugPacketV4(lib_ctx, manual_sa, dst_ipv4, ...)` → 📎 见 tainted.list
│       └── [L11753] `IPSEC_PKT_DebugPacketV4(lib_ctx, manual_sa, dst_ipv4, ...)` → 📎 见 tainted.list
└── [L11830] `dst_ipv4 = __builtin_bswap32(RAW_U32(parse_state, 52))`
    └── dst_ipv4 🔴 TAINTED
        └── [L11843] `IPSEC_PKT_DebugPacketV4(lib_ctx, manual_sa, dst_ipv4, ...)` → 📎 见 tainted.list

## 污点溯源
- `x` 接收自 `RAW_U32(parse_state, 52)` → 读取自外部网络包解析后的 `parse_state[52:56]` (PST_DST4_RAW)
- `parse_state` 初始来源: `IPSEC_PKT_ParseAndVerifyHdrV4` 写入 (L11253)

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| x → dst_ipv4 | 📎 子函数 | L11640 | 传入 IPSEC_PKT_DebugPacketV4 |
| x → dst_ipv4 | 📎 子函数 | L11753 | 传入 IPSEC_PKT_DebugPacketV4 |
| x → dst_ipv4 | 📎 子函数 | L11843 | 传入 IPSEC_PKT_DebugPacketV4 |