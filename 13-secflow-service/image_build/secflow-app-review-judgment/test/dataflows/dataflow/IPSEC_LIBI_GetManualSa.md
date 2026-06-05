## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIBI_GetManualSa

## 函数信息
- 文件: `libipsec.c`
- 签名: `int64_t IPSEC_LIBI_GetManualSa(int64_t lib_ctx, int64_t manual_sa_cfg, uint32_t *spi_or_ports)`
- 功能: 根据 `parse_state[64]` 缓冲区中的网络数据构造 SADB 查找键，查询 SA 数据库

## 污点源

### INPUT: `manual_sa_cfg` (int64_t → parse_state[64]) 🔴 TAINTED
- **来源**: 调用者处 `uint8_t parse_state[64]` 缓冲区，内容由 `IPSEC_PKT_ParseAndVerifyHdr` / `ParseAndVerifyHdrV4` 从网络 mbuf/IP 头的各字段填充后，以 `(int64_t)parse_state` 作为 `manual_sa_cfg` 传入
- **污点类型**: 外部网络输入

## 污点传播路径

```
### INPUT: manual_sa_cfg (int64_t → parse_state[64]) 🔴 TAINTED
│
├── [L10210] if (RAW_U8(manual_sa_cfg, 28) == 1)
│   ├── [L10211] if (spi_or_ports == NULL) → 🟢 CLEANED（空指针检查）
│   ├── [L10213] if (spi_or_ports[1] != 0)
│   │   ├── [L10214] RAW_U32(&lookup_key, 0) = spi_or_ports[1] → 🟢 CLEANED
│   │   └── [L10217] RAW_U32(&lookup_key, 0) = spi_or_ports[0] → 🟢 CLEANED
│   │   └── [L10215/L10218] RAW_U8(&lookup_key, 4) = 50/51 → 🟢 CLEANED
│   └── [L10220] RAW_U8(&lookup_key, 5) = 0 → 🟢 CLEANED
│       └── [L10227] VOS_AVL3_Find(..., &lookup_key, ...)
│           → 查找键源自 control_info（非 parse_state），🟢 CLEANED
│
└── [L10221] else:  RAW_U8(manual_sa_cfg, 28) != 1 → 🔴 TAINTED 分支
    │
    ├── [L10222] RAW_U32(&lookup_key, 0) = RAW_U32(manual_sa_cfg, 12)
    │   → lookup_key[0..3] 🔴 TAINTED
    │   → 读取 parse_state[12..15] (PST_SPI)，值来自网络 mbuf 中的 ESP/AH 头
    │   → ⚠️ DIRECT_SINK: 污点 SPI 值驱动 SA 查找键构造
    │
    ├── [L10223] RAW_U8(&lookup_key, 4) = RAW_U8(manual_sa_cfg, 8)
    │   → lookup_key[4] 🔴 TAINTED
    │   → 读取 parse_state[8] (PST_PREV_PROTO)，值来自网络 IP 头的协议字段
    │   → ⚠️ DIRECT_SINK: 污点协议字节参与 SA 查找键构造
    │
    ├── [L10224] RAW_U8(&lookup_key, 5) = 1 → 🟢 CLEANED（常量赋值）
    │
    ├── [L10227] VOS_AVL3_Find(lib_ctx + 120, &lookup_key, lib_ctx + 144)
    │   → ⚠️ DIRECT_SINK: lookup_key[0..4] 完全由网络数据构造（SPI + 协议），作为 SADB 查找键
    │
    └── [L10228] if (sa_entry != 0)
        └── [L10229] VOS_AVL3_Find(lib_ctx + 76, (const void *)(sa_entry + 132), lib_ctx + 100)
            → ⚠️ DIRECT_SINK: sa_entry 来自污点键控的第一次查找，其指针用于第二次查找
            └── [L10230] RETURN_GUARDED(sa_entry) → 📌 USED（SA 句柄返回调用者）
```

## 新导入的污点对象

| 对象名 | 类型 | 构造方式 | 污点来源 |
|--------|------|----------|----------|
| `lookup_key` | 结构体 | RAW_U32(&lookup_key, 0) = RAW_U32(manual_sa_cfg, 12); RAW_U8(&lookup_key, 4) = RAW_U8(manual_sa_cfg, 8) | manual_sa_cfg → parse_state[64] (网络数据) |

### lookup_key 传播下游
```
lookup_key 🔴 TAINTED (由 manual_sa_cfg 在 L10222-L10223 构造)
└── [L10227] VOS_AVL3_Find(..., &lookup_key, ...) → ⚠️ DIRECT_SINK
```

## 污点终点汇总

| 脏数据 | 终点类型 | 位置 | 说明 |
|--------|----------|------|------|
| manual_sa_cfg (parse_state[64]) | ⚠️ DIRECT_SINK | L10222 | 污点 SPI 值驱动 SA 查找键构造 |
| manual_sa_cfg (parse_state[64]) | ⚠️ DIRECT_SINK | L10223 | 污点协议字节参与 SA 查找键构造 |
| manual_sa_cfg (parse_state[64]) | ⚠️ DIRECT_SINK | L10227 | lookup_key 由网络数据构造，驱动 SADB 查找 |
| manual_sa_cfg (parse_state[64]) | ⚠️ DIRECT_SINK | L10229 | sa_entry 来自污点键控查找，作为二次查找参数 |
| manual_sa_cfg (parse_state[64]) | 📌 USED | L10230 | sa_entry 作为 SA 句柄返回给调用者 |

## 关键风险

1. **网络数据驱动 SADB 查找键**: `parse_state[12..15]` 中的 SPI 值和 `parse_state[8]` 中的协议值完全由网络数据控制
2. **SA 查找键构造**: 两个 DIRECT_SINK 标记点（L10222, L10223）确认污点数据参与 SADB 查找键构造
3. **双重查找依赖**: 第二次 VOS_AVL3_Find 的输入依赖于第一次查找结果，而第一次查找键完全由网络数据控制