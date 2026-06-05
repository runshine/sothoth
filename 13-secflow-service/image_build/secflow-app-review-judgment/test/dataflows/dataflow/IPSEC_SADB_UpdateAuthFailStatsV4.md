## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `result` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SADB_UpdateAuthFailStatsV4

## 函数信息
- 文件: libipsec.c
- 签名: `void IPSEC_SADB_UpdateAuthFailStatsV4(void *result, unsigned int aTableId, unsigned int aDirection)`

## 污点源
| 变量 | 类型 | 状态 | 说明 |
|------|------|------|------|
| result | void* | 🔴 TAINTED | 外部输入参数，作为指向统计结构体的指针 |

## 新导入的污点对象（来自当前函数内部分析）
| 变量 | 来源 | 状态 | 说明 |
|------|------|------|------|
| result_ctx | 由 `result_ctx = result` 在 L15562 赋值派生 | 🔴 TAINTED | 内部上下文指针，从 result 派生 |

---

## 完整传播路径树状图

### INPUT-1: result (void*) 🔴 TAINTED
├── [L15556] case 6: if (result) ++RAW_U32((void *)result, 304)
│   └── ⚠️ DIRECT_SINK: 污点指针作为基址访问结构体成员，偏移304
├── [L15560] case 8: if (result) ++RAW_U32((void *)result, 312)
│   └── ⚠️ DIRECT_SINK: 污点指针作为基址访问结构体成员，偏移312
└── [L15562] case 2: result_ctx = result → result_ctx 🔴 TAINTED
    ├── [L15566] if (result_ctx) → 条件判断使用（干净逻辑）
    ├── [L15567] result = (unsigned int)(RAW_U32((void *)result_ctx, 288) + 1)
    │   └── ⚠️ DIRECT_SINK: result_ctx 读取偏移288成员
    └── [L15568] RAW_U32((void *)result_ctx, 288) = (uint32_t)result
        └── ⚠️ DIRECT_SINK: result_ctx 写入偏移288成员

---

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| result | ⚠️ DIRECT_SINK | L15556 | 污点指针作为基址访问结构体成员，偏移304 |
| result | ⚠️ DIRECT_SINK | L15560 | 污点指针作为基址访问结构体成员，偏移312 |
| result_ctx | ⚠️ DIRECT_SINK | L15567 | result_ctx 读取偏移288成员 |
| result_ctx | ⚠️ DIRECT_SINK | L15568 | result_ctx 写入偏移288成员 |

---

## 跟入表（子函数调用）
| 文件 | 函数 | 调用位置 | 接收的形参 |
|------|------|---------|----------|
| 无直接子函数调用 | — | — | — |

**说明**: `RAW_U32` 为宏展开非函数调用；`VRP_Assert` 调用中 `result` 用于赋值覆盖而非参数传递。