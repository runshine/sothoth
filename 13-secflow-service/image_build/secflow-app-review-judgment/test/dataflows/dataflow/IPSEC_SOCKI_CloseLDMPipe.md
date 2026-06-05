## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `pipe_desc` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SOCKI_CloseLDMPipe

## 函数信息
- 文件: libipsec.c
- 函数签名: `void IPSEC_SOCKI_CloseLDMPipe(int64_t pipe_desc)`

## 污点源

### pipe_desc 🔴 TAINTED
外部传入的管道描述符指针，作为核心污点数据源。

## 新导入的污点对象

无（此函数未调用Recv/Read/Get等函数导入新的污点载体）

## 传播路径

### INPUT-1: pipe_desc (int64_t) 🔴 TAINTED
├── [L24596] pipe_field_36 = RAW_U32((void *)pipe_desc, 36)
│   └── pipe_field_36 🔴 TAINTED (从tainted指针偏移读取)
│       └── [L24597] if (pipe_field_36 != 0xFFFFFFFFu) VRP_PipeCloseLocal(pipe_field_36)
│           ├── 📎 CALLEE: VRP_PipeCloseLocal (L24597) - 管道ID参数
│           └── ⚠️ DIRECT_SINK: 提取的管道ID传入关闭操作，ID值由污点数据控制
├── [L24598] IPSEC_MGTI_TimerDelete((uint64_t *)(pipe_desc + 48), 6, 0, ctx_base)
│   └── 📎 CALLEE: IPSEC_MGTI_TimerDelete (L24598) - timer_slot参数
├── [L24599] IPSEC_MGTI_TimerDelete((uint64_t *)(pipe_desc + 56), 7, 0, ctx_base)
│   └── 📎 CALLEE: IPSEC_MGTI_TimerDelete (L24599) - timer_slot参数
└── [L24600] RAW_U32((void *)pipe_desc, 44) = 0
    └── ⚠️ DIRECT_SINK: 写入tainted-derived地址pipe_desc+44，偏移量可控

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| pipe_desc | 📎 CALLEE: VRP_PipeCloseLocal | L24597 | 提取的pipe_id作为管道关闭参数 |
| pipe_desc | 📎 CALLEE: IPSEC_MGTI_TimerDelete | L24598 | pipe_desc+48作为timer_slot |
| pipe_desc | 📎 CALLEE: IPSEC_MGTI_TimerDelete | L24599 | pipe_desc+56作为timer_slot |
| pipe_desc | ⚠️ DIRECT_SINK | L24597 | 管道ID值受污点数据控制 |
| pipe_desc | ⚠️ DIRECT_SINK | L24600 | 写入tainted-derived地址pipe_desc+44 |

## 高危模式标记

| 模式 | 位置 | 风险说明 |
|------|------|----------|
| 指针偏移读取 | L24596, L24598, L24599, L24600 | 从外部污点指针读取多字段数据 |
| 写入污点衍生地址 | L24600 | 向可控偏移地址写入数据 |
| 条件分支使用污点值 | L24597 | pipe_id值用于条件判断和关闭操作 |