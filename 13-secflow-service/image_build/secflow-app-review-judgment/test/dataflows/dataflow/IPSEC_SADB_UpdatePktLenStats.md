## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `a2` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `a3` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SADB_UpdatePktLenStats

## 函数信息
- 文件: libipsec.c
- 签名: `IPSEC_SADB_UpdatePktLenStats(int64_t result, int64_t a2, int a3)`

## 污点源

### INPUT-1: result (int64_t) 🔴 TAINTED
外部输入参数，作为 stats 结构体指针使用

### INPUT-2: a2 (int64_t) 🔴 TAINTED
外部输入参数，作为 stats 结构体指针使用

### INPUT-3: a3 (int) 🔴 TAINTED
外部输入参数，用于条件判断控制流

---

## 数据流树状图

### INPUT-1: result (int64_t) 🔴 TAINTED
```
result (int64_t) 🔴 TAINTED
│
└──[L15368] if (result) ++RAW_U32((void *)result, 256)
    └── ⚠️ DIRECT_SINK: 污染指针 result 用于内存解引用，偏移量 256 为常量
        └── 条件判断 result 非空 → 仅检查指针有效性，不影响数据流

result (int64_t) 🔴 TAINTED
│
└──[L15372] if (result) ++RAW_U32((void *)result, 272)
    └── ⚠️ DIRECT_SINK: 污染指针 result 用于内存解引用，偏移量 272 为常量
```

### INPUT-2: a2 (int64_t) 🔴 TAINTED
```
a2 (int64_t) 🔴 TAINTED
│
└──[L15367] if (a2) ++RAW_U32((void *)a2, 4072)
    └── ⚠️ DIRECT_SINK: 污染指针 a2 用于内存解引用，偏移量 4072 为常量

a2 (int64_t) 🔴 TAINTED
│
└──[L15371] if (a2) ++RAW_U32((void *)a2, 4088)
    └── ⚠️ DIRECT_SINK: 污染指针 a2 用于内存解引用，偏移量 4088 为常量
```

### INPUT-3: a3 (int) 🔴 TAINTED
```
a3 (int) 🔴 TAINTED
│
└──[L15366] if (a3 == 23) → 仅用于条件判断，无数据传播
│   ├── [L15367] if (a2) ++RAW_U32((void *)a2, 4072); → 无 a3 参与
│   └── [L15368] if (result) ++RAW_U32((void *)result, 256); → 无 a3 参与
├── [L15370] else if (a3 == 27) → 仅用于条件判断，无数据传播
│   ├── [L15371] if (a2) ++RAW_U32((void *)a2, 4088); → 无 a3 参与
│   └── [L15372] if (result) ++RAW_U32((void *)result, 272); → 无 a3 参与
└── [L15374] return result → 返回值与 a3 完全独立
    └── 🟢 a3 终止于 L15366/L15370，仅作为等值比较的控制流键值，无数据传播
```

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| result | ⚠️ DIRECT_SINK | L15368 | 污染指针 result 用于内存解引用，偏移量 256 为常量 |
| result | ⚠️ DIRECT_SINK | L15372 | 污染指针 result 用于内存解引用，偏移量 272 为常量 |
| a2 | ⚠️ DIRECT_SINK | L15367 | 污染指针 a2 用于内存解引用，偏移量 4072 为常量 |
| a2 | ⚠️ DIRECT_SINK | L15371 | 污染指针 a2 用于内存解引用，偏移量 4088 为常量 |
| a3 | 🟢 终止 | L15366/L15370 | 仅作为等值比较的控制流键值，无数据传播 |

---

## 新导入的污点对象
无 — 本函数未通过 `Recv/Read/Get` 等调用导入新对象

---

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| (无) | — | — |

---

## 安全评估
- result: 偏移量 256、272 为硬编码常量，未从 result 派生
- a2: 偏移量 4072、4088 为硬编码常量，未从 a2 派生
- result 和 a2 仅被检查非空后作为内存基址解引用，无边界检查
- 若 result 或 a2 指向攻击者可控的内存区域，可导致内存覆写
- a3: 仅用于控制流条件判断，无数据传播