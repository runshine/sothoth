## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: CTX_LOG

## 函数信息
- 文件: libipsec.c
- 行号: L23973-L23997 (宏定义)
- 签名: `CTX_LOG(ctx, msg, ...)`

## 污点源

| 变量 | 类型 | 状态 | 说明 |
|------|------|------|------|
| ctx | void* | 🔴 TAINTED | 外部传入的上下文指针 |

## 新导入的污点对象

| 对象 | 导入方式 | 状态 | 说明 |
|------|---------|------|------|
| 无 | - | - | 本宏未通过输出参数导入新污点对象 |

## 传播路径图

### ctx 🔴 TAINTED
```
├── [L23975] if (RAW_U8((void*)(ctx), 392) == 1) → 控制流判断
├── [L23976] IPSEC_MakeDbgCompStrSetter((ctx), ...) → 📎 见跟入列表 (ctx作为第1参数)
├── [L23978] IPSEC_Print_File((ctx), 1, (const char*)(ctx + 424))
│   ├── 📎 见跟入列表 (ctx作为第1参数)
│   └── ⚠️ DIRECT_SINK: (ctx + 424) 指针运算，偏移量来自污点ctx
├── [L23980] RAW_U32((void*)(ctx), 4) → 🔴 TAINTED (从ctx提取值)
├── [L23982] RAW_U64((void*)(ctx), 416) → 🔴 TAINTED (从ctx提取值)
├── [L23984] (const char*)(ctx + 424) → ⚠️ DIRECT_SINK (字符串指针来自污点偏移)
└── [L23986] SSP_Debug(RAW_U32(ctx,4), ..., (ctx+424))
    └── 🟡 EXPORT (标准库函数，不追踪内部)

├── [L23988] else if (RAW_U8((void*)(ctx), 391) == 1) → 控制流判断
├── [L23989] IPSEC_MakeDbgCompStrSetter((ctx), ...) → 📎 见跟入列表
├── [L23991] IPSEC_Print_File((ctx), 1, (const char*)(ctx + 424))
│   ├── 📎 见跟入列表
│   └── ⚠️ DIRECT_SINK: 同 L23978
├── [L23993] RAW_U32((void*)(ctx), 4) → 🔴 TAINTED
├── [L23994] RAW_U64((void*)(ctx), 416) → 🔴 TAINTED
├── [L23995] (const char*)(ctx + 424) → ⚠️ DIRECT_SINK
└── [L23997] SSP_Debug(...) → 🟡 EXPORT
```

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| ctx | IPSEC_MakeDbgCompStrSetter | L23976, L23989 | 上下文指针作为第1参数传入 |
| ctx, (ctx+424) | IPSEC_Print_File | L23978, L23991 | 上下文指针及污点偏移计算出的字符串指针 |
| ctx提取值 | SSP_Debug | L23986, L23997 | 从ctx偏移4和416处提取的uint32/uint64值 (标准库) |

## 关键危险标记 (⚠️ DIRECT_SINK)

| 位置 | 危险操作 |
|------|---------|
| L23978, L23991 | `(ctx + 424)` → `const char*` — 污点指针算术，产生任意内存地址字符串 |
| L23984, L23995 | 传入 `IPSEC_Print_File` 和 `SSP_Debug` 作为格式字符串，可能导致格式化字符串漏洞 |

## 备注
- `CTX_LOG` 是宏定义 (L23973-L23994)，非函数
- 所有子函数定义未在当前分析范围内找到，标记为 🟡 EXPORT
- `SSP_Debug` 为标准库函数，按策略不追踪其内部实现