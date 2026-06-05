## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `lib_ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIB_LOG_IF_ENABLED

## 函数信息
- 文件: libipsec.c
- 行号: L4266-L4269（宏展开至 L4253-L4262）
- 签名: `void IPSEC_LIB_LOG_IF_ENABLED(void *lib_ctx)`

## 污点源
- lib_ctx (void*) 🔴 TAINTED — 外部调用方传入的 libipsec 库上下文指针

## 传播路径

### INPUT: lib_ctx (void*) 🔴 TAINTED
```
├── [L4266] RAW_U8(lib_ctx, 400)
│   └── 仅用于条件判断（控制流依赖，无新变量）
└── [L4267] IPSEC_LIB_LOG_WITH_CODE(lib_ctx, ...)
    └── 宏展开 L4253-L4262:
        ├── IPSEC_MakeDbgLibStrSetter(lib_ctx, 5, ...) 📎 外部函数
        │   └── 接收 lib_ctx 作为第一参数
        ├── RAW_U32(lib_ctx, 408)
        │   └── 直接传参，无新变量
        ├── RAW_U64(lib_ctx, 440)
        │   └── 直接传参，无新变量
        └── (const char *)((uint8_t *)lib_ctx + 448)
            └── ⚠️ DIRECT_SINK: 指针算术构造字符串指针，传入 SSP_Debug 的 %s 参数

### INPUT: lib_ctx (void*) 🔴 TAINTED（else-if 分支）
└── [L4269] RAW_U8(lib_ctx, 403) → 仅用于条件判断
    └── IPSEC_LIB_LOG_WITH_CODE(lib_ctx, ...) → 同上传播路径
```

## ⚠️ DIRECT_SINK

| 位置 | 操作 | 风险描述 |
|------|------|----------|
| L4261 (宏展开) | `(const char *)((uint8_t *)lib_ctx + 448)` | 指针算术将 lib_ctx 结构体偏移 448 处构造为字符串指针，传入 SSP_Debug 的 %s 参数 |

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| lib_ctx | 📎 IPSEC_MakeDbgLibStrSetter | L4254 | extern 函数 |
| lib_ctx | 📎 SSP_Debug | L4261 | extern 函数 |

## 新导入的污点对象
- 无（宏展开体内无 Recv/Read/Get/Decode/Parse 类调用，无新载体引入）