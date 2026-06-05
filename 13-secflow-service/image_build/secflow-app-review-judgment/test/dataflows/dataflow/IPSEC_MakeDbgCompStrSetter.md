## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_MakeDbgCompStrSetter

## 函数信息
- 文件: libipsec.c
- 函数签名: `void IPSEC_MakeDbgCompStrSetter(int64_t ctx, int32_t comp_id, int32_t line_no, const char *fmt, ...)`

## 污点源

| 序号 | 变量名 | 类型 | 状态 | 说明 |
|------|--------|------|------|------|
| INPUT-1 | ctx | int64_t | 🔴 TAINTED | 外部输入参数（上下文句柄） |

## 新导入的污点对象

| 变量名 | 类型 | 派生位置 | 派生方式 |
|--------|------|----------|----------|
| out_str | char* | L19794 | `out_str = (char *)(ctx + 424)` — 通过污点偏移派生指针 |

## 传播路径

```
### INPUT-1: ctx (int64_t) 🔴 TAINTED
├── [L19794] out_str = (char *)(ctx + 424) → out_str 🔴 TAINTED (新导入)
│   └── [L19795] snprintf_truncated_s(out_str, 513, "[IPSEC] <%04d%05d>: ", comp_id, line_no)
│       └── ⚠️ DIRECT_SINK: 写入 ctx+424 scratch buffer
├── [L19798] memset_s(assert_text, 100, 0)
│   └── 干净操作，无污点传播
├── [L19803] prefix_len = VOS_StrLen(out_str) → prefix_len 🟢 CLEANED
│   └── 长度测量，不传播污点
├── [L19804] memset_s(va_scratch, 32, 0)
│   └── 干净操作
├── [L19806] va_start(ap, fmt)
│   └── 初始化变参列表，fmt来自外部
├── [L19807] vsnprintf_truncated_s(out_str + prefix_len, 513 - prefix_len, fmt, ap)
│   └── ⚠️ DIRECT_SINK: 用户控制fmt写入 ctx+424+prefix_len 区域
└── [L19815] RETURN_GUARDED(0)
    └── 干净返回
```

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| ctx → out_str | ⚠️ DIRECT_SINK | L19795 | snprintf_truncated_s 写入 ctx+424 scratch buffer |
| ctx + prefix_len | ⚠️ DIRECT_SINK | L19807 | vsnprintf_truncated_s 用户控制fmt写入 ctx+424+prefix_len 区域 |

## 安全判断

| 检查点 | 结果 | 说明 |
|--------|------|------|
| 缓冲区溢出风险 | ⚠️ 警告 | 513字节缓冲区，写入长度受prefix_len和fmt控制 |
| 偏移量可控性 | ⚠️ 警告 | ctx+424为固定偏移，prefix_len来自污点字符串长度测量 |
| 格式化字符串 | ⚠️ 警告 | fmt参数来自外部，可控制vsnprintf内容 |