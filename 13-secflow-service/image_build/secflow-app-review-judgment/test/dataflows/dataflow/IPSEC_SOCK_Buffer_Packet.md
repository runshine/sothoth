## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `ctx_base` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SOCK_Buffer_Packet

## 函数信息
- 文件: libipsec.c
- 签名: `int IPSEC_SOCK_Buffer_Packet(int64_t ctx_base, ...)`

## 污点源
| 参数 | 类型 | 状态 |
|------|------|------|
| ctx_base | int64_t | 🔴 TAINTED - 外部输入参数 |

## 新导入的污点对象
- 无 — 当前函数未调用 Recv/Read/Get/Decode/Parse 类函数，无输出参数导入新污点

## 传播路径

### INPUT: ctx_base (int64_t) 🔴 TAINTED
```
├── [L25491] RAW_U64((void *)ctx_base, 28) → ⚠️ DIRECT_SINK: 污染值作为 heap 指针参数
│   └── VRP_Malloc_F(RAW_U64((void *)ctx_base,28), g_aucVrpMemPt, 16, ...)
│       → 可将内存分配重定向到任意地址（基于 ctx_base+28 处的可控 64 位值）
│
└── [L25509] ctx_base 传入 CTX_LOG 宏
    ├── [L25509] RAW_U8((void *)ctx_base, 392) == 1 → 条件判断，无新污点
    └── [L25509] CTX_LOG(ctx_base, 2698, ...) → 日志宏，仅提取调试字段
        └── 宏内 RAW_U32/RAW_U64 仅读取字段(4,416)，不产生新污点载体
```

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| ctx_base | ⚠️ DIRECT_SINK | L25491 | 污染值通过 RAW_U64((void*)ctx_base,28) 作为堆指针参数，VRP_Malloc_F 可将内存分配重定向到任意地址 |
| ctx_base | CTX_LOG (宏) | L25509 | 日志宏调用，接收 ctx_base 作为第一个参数 |