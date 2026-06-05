## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `selector_words` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `algo_dbg_word` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSECL_DBG_AhPktAlgo

## 函数信息
- 文件: libipsec.c
- 函数签名:
```c
int64_t IPSECL_DBG_AhPktAlgo(
    int64_t lib_ctx,
    unsigned short **sa_type_desc,
    int64_t sadb_entry,
    int64_t selector1,
    int64_t selector2,
    unsigned int *packet_meta)
```

## 污点源
| 编号 | 参数 | 类型 | 状态 |
|------|------|------|------|
| INPUT-1 | selector1 | int64_t | 🔴 TAINTED |
| INPUT-2 | selector2 | int64_t | 🔴 TAINTED |
| INPUT-3 | packet_meta | unsigned int* | 🔴 TAINTED — 外部网络输入参数 |

## 新导入的污点对象
| 变量 | 类型 | 来源 | 行号 |
|------|------|------|------|
| dbg_mode | unsigned int | `*((uint8_t *)packet_meta + 4)` | L7865 |
| dbg_tag | unsigned int | `*packet_meta` | L7866 |

## 传播路径

### INPUT-1: selector1 (int64_t) 🔴 TAINTED
```
selector1 🔴 TAINTED
├── [L7872] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7878] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7900] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7905] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7915] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7921] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
└── [L7948] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
```

### INPUT-2: selector2 (int64_t) 🔴 TAINTED
```
selector2 🔴 TAINTED
├── [L7872] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7878] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7900] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7905] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7915] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7921] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
└── [L7948] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
```

### INPUT-3: packet_meta (unsigned int*) 🔴 TAINTED
```
packet_meta 🔴 TAINTED
├── [L7865] dbg_mode = *((uint8_t *)packet_meta + 4) → dbg_mode 🔴 TAINTED (新对象)
│   └── [L7873] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
│   └── [L7878] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
│   └── [L7900] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
│   └── [L7905] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
│   └── [L7915] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
│   └── [L7921] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
│   └── [L7940] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
│   └── [L7948] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
└── [L7866] dbg_tag = *packet_meta → dbg_tag 🔴 TAINTED (新对象)
    └── (同上, 8次调用传递 dbg_tag 作为参数)
```

## 接收此污点的子函数汇总

| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| IPSEC_PKT_DebugPacket | L7872, L7878, L7900, L7905, L7915, L7921, L7948 | selector1, selector2 |
| IPSEC_PKT_DebugPacket | L7873, L7878, L7900, L7905, L7915, L7921, L7940, L7948 | dbg_mode, dbg_tag |

## 安全备注

- 函数 `IPSECL_DBG_AhPktAlgo` 作为**调度器**角色，根据 `sa_type` 和 `dbg_mode` 条件将污点数据路由到 `IPSEC_PKT_DebugPacket` 的多个调用点
- 本函数体内，污点参数仅作为函数参数传递，未进行指针运算、数组索引或内存操作
- 新导入的污点对象 `dbg_mode` 和 `dbg_tag` 均源自 `packet_meta` 的直接解引用
- 未发现 DIRECT_SINK 模式（无 memcpy、整数截断、越界索引等）