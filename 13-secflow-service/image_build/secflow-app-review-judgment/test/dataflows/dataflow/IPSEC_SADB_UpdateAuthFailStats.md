## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `a2` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `a3` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SADB_UpdateAuthFailStats

## 函数信息
- 文件: libipsec.c
- 行号: L15334-L15355
- 签名: `int IPSEC_SADB_UpdateAuthFailStats(int64_t a2, int a3)`

## 数据流树状图

### INPUT-1: a2 (int64_t) 🔴 TAINTED
```
├── [L15337] case 6: if (a2) ++RAW_U32((void*)a2, 4004) → ⚠️ DIRECT_SINK (指针解引用写内存)
├── [L15340] case 8: if (a2) ++RAW_U32((void*)a2, 4012) → ⚠️ DIRECT_SINK (指针解引用写内存)
└── [L15347] case 2: if (a2) result = VRP_Assert(a2) → 🟡 EXPORT (标准库/外部函数)
    (a2 仅作布尔守卫判断，未直接作为污点数据传递)
```

### INPUT-2: a3 (int) 🔴 TAINTED
```
├── [L15334] switch(a3) → 分支路由，控制执行 case 2/6/8
│   │
│   ├── case 2:
│   │   ├── [L15346] result_ctx = result → result_ctx 继承 result 状态
│   │   └── [L15351] RAW_U32((void*)result_ctx, 172) = (uint32_t)result → ⚠️ DIRECT_SINK
│   │       (a3值触发此分支，内存写偏移为常量172)
│   │
│   ├── case 6:
│   │   └── [L15338] if (result) ++RAW_U32((void*)result, 188) → ⚠️ DIRECT_SINK
│   │       (a3值触发此分支，内存写偏移为常量188)
│   │
│   └── case 8:
│       └── [L15343] if (result) ++RAW_U32((void*)result, 196) → ⚠️ DIRECT_SINK
│           (a3值触发此分支，内存写偏移为常量196)
│
└── [L15355] return result → 📌 USED
```

## 新导入的污点对象
- **无新对象导入** — `a2` 和 `a3` 仅用于分支判断和内存操作，未参与 `Recv/Read/Copy/Decode/Parse` 等导入式调用

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| a2 | DIRECT_SINK | L15337 | 指针解引用写内存 (offset: 4004) |
| a2 | DIRECT_SINK | L15340 | 指针解引用写内存 (offset: 4012) |
| a2 | EXPORT | L15347 | 传入 VRP_Assert (a2 仅作布尔守卫) |
| a3 | BRANCH_CTRL | L15334 | 分支选择器，控制执行路径 |
| result | DIRECT_SINK | L15338 | case 6 内存写 (offset: 188) |
| result | DIRECT_SINK | L15343 | case 8 内存写 (offset: 196) |
| result | DIRECT_SINK | L15351 | case 2 内存写 (offset: 172) |

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| 无 | — | — |

**备注**: `a2` 和 `a3` 未作为实参传递给任何下游函数（本函数为叶函数）