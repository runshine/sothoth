## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `lib_ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `flow_id=dbg_flow_id` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `algo_word=packet_info[14]` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSECL_DBG_EspPktAlgoV4

## 函数信息
- 文件: libipsec.c
- 签名: `void IPSECL_DBG_EspPktAlgoV4(void *lib_ctx, esp_sa_stats *sa_stats, unsigned int flow_id, unsigned int *packet_meta)`
- 功能: ESP包算法调试信息输出，处理IPsec库上下文和ESP安全关联统计

---

## 污点源汇总

| 污点变量 | 类型 | 来源 | 说明 |
|---------|------|------|------|
| `lib_ctx` | void* | 外部库上下文指针，来自网络/IPsec库初始化 | 🔴 TAINTED |
| `flow_id` | unsigned int | `__builtin_bswap32(packet_info[13])`，网络包中的SPI/flow selector | 🔴 TAINTED |
| `packet_meta` | unsigned int* | 外部污点对象 `&algo_dbg_word` 传入，承载 packet_info[14] | 🔴 TAINTED |

---

## 新导入的污点对象（函数内部派生）

| 对象 | 类型 | 来源 | 行号 |
|-----|------|------|------|
| `dbg_mode` | unsigned int | `*((uint8_t*)packet_meta + 4)` 从 packet_meta+4 提取 | L8199 |
| `dbg_tag` | unsigned int | `*packet_meta` 从 packet_meta 提取 | L8200 |

---

## 传播路径

### INPUT-1: lib_ctx (void*) 🔴 TAINTED
```
lib_ctx 🔴 TAINTED
├── [L8197] if (lib_ctx) → 条件判断
├── [L8198] RAW_U8((void *)lib_ctx, 401) == 1 → 🟡 CONTROL_USED（调试模式标志）
│   ├── [L8210] IPSEC_PKT_DebugPacketV4(lib_ctx, sa_stats, flow_id, dbg_mode, dbg_tag) → 📎 子函数
│   ├── [L8220] IPSEC_MakeDbgLibStrSetter(lib_ctx, ..., algo_word, ...) → 📎 子函数
│   └── [L8223] SSP_Debug(..., (const char *)(lib_ctx + 448)) → ⚠️ DIRECT_SINK
├── [L8203] RAW_U8((void *)lib_ctx, 403) != 1 → 🟡 CONTROL_USED
│   └── [L8214] IPSEC_PKT_DebugPacketV4(lib_ctx, sa_stats, flow_id, dbg_mode, dbg_tag) → 📎 子函数
├── [L8229] if (lib_ctx) → 条件判断
├── [L8258] if (lib_ctx) → 条件判断
├── [L8259] RAW_U8((void *)lib_ctx, 401) == 1 → 🟡 CONTROL_USED
│   └── [L8269] IPSEC_PKT_DebugPacketV4(...) → 📎 子函数
├── [L8264] RAW_U8((void *)lib_ctx, 403) != 1 → 🟡 CONTROL_USED
│   └── [L8271] IPSEC_PKT_DebugPacketV4(...) → 📎 子函数
├── [L8279] IPSEC_MakeDbgLibStrSetter(lib_ctx, ..., algo_word, ...) → 📎 子函数
├── [L8300] if (lib_ctx) → 条件判断
├── [L8301] RAW_U8((void *)lib_ctx, 401) == 1 → 🟡 CONTROL_USED
│   └── [L8337] IPSEC_PKT_DebugPacketV4(...) → 📎 子函数
├── [L8306] RAW_U8((void *)lib_ctx, 403) == 1 → 🟡 CONTROL_USED
├── [L8313] RAW_U8((void *)lib_ctx, 401) == 1 → 🟡 CONTROL_USED
│   └── [L8317] IPSEC_PKT_DebugPacketV4(...) → 📎 子函数
├── [L8320] RAW_U8((void *)lib_ctx, 403) != 1 → 🟡 CONTROL_USED
├── [L8321] IPSEC_PKT_DebugPacketV4(...) → 📎 子函数
├── [L8327] IPSEC_MakeDbgLibStrSetter(lib_ctx, ..., algo_word, ...) → 📎 子函数
├── [L8328] SSP_Debug(..., (const char *)(lib_ctx + 448)) → ⚠️ DIRECT_SINK
├── [L8335] RAW_U8((void *)lib_ctx, 401) == 1 → 🟡 CONTROL_USED
├── [L8342] result = RAW_U8((void *)lib_ctx, 403) → 🟡 CONTROL_USED
│   └── [L8346] IPSEC_PKT_DebugPacketV4(...) → 📎 子函数
├── [L8351] IPSEC_MakeDbgLibStrSetter(lib_ctx, ..., algo_word, ...) → 📎 子函数
└── [L8352] SSP_Debug(..., (const char *)(lib_ctx + 448)) → ⚠️ DIRECT_SINK
```

### INPUT-2: flow_id (unsigned int) 🔴 TAINTED
```
flow_id 🔴 TAINTED
├── [L8210] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数（sa_type==3分支）
├── [L8215] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数
├── [L8246] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数（sa_type==5分支）
├── [L8251] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数
├── [L8269] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数（默认分支）
├── [L8276] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数
├── [L8286] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数（after_sa_type_log分支）
├── [L8291] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数
├── [L8302] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数（auth_alg_log分支）
└── [L8308] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数
```

### INPUT-3: packet_meta (unsigned int*) 🔴 TAINTED
```
packet_meta 🔴 TAINTED
├── [L8199] dbg_mode = *((uint8_t*)packet_meta + 4);
│   └── dbg_mode 🔴 TAINTED
│       └── [L8210,L8214,L8215,L8246,L8251,L8269,L8271,L8276,L8286,L8291,L8302,L8308,L8317,L8321,L8337,L8346]
│           共16次传入 IPSEC_PKT_DebugPacketV4 → 📎 子函数
└── [L8200] dbg_tag = *packet_meta;
    └── dbg_tag 🔴 TAINTED
        └── [L8210,L8214,L8215,L8246,L8251,L8269,L8271,L8276,L8286,L8291,L8302,L8308,L8317,L8321,L8337,L8346]
            共16次传入 IPSEC_PKT_DebugPacketV4 → 📎 子函数
```

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| lib_ctx | ⚠️ DIRECT_SINK | L8223 | lib_ctx+448 作为 (const char*) 传入 SSP_Debug |
| lib_ctx | ⚠️ DIRECT_SINK | L8328 | 同上 |
| lib_ctx | ⚠️ DIRECT_SINK | L8352 | 同上 |
| lib_ctx | 🟡 CONTROL_USED | L8198,L8203,L8259,L8264,L8301,L8306,L8313,L8320,L8335,L8342 | 调试模式标志用于条件分支 |
| lib_ctx | 📎 子函数 | 16处 | 传递给调试和日志函数 |
| flow_id | 📎 子函数 | 10处 | 作为只读参数传递给 IPSEC_PKT_DebugPacketV4 |
| dbg_mode | 📎 子函数 | 16处 | 作为参数传递给 IPSEC_PKT_DebugPacketV4 |
| dbg_tag | 📎 子函数 | 16处 | 作为参数传递给 IPSEC_PKT_DebugPacketV4 |