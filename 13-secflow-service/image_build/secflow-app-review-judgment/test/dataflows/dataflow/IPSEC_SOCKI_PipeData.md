## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `pipe_id` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `msg_type` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `target_pid` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SOCKI_PipeData

## 函数信息
- 文件: libipsec.c
- 行号: L26803-L26821
- 签名: `int64_t IPSEC_SOCKI_PipeData(int pipe_id, unsigned int recv_len, unsigned int arg3, int64_t ctx_base, unsigned int trace_target)`

## 函数体分析

```c
int64_t IPSEC_SOCKI_PipeData(int pipe_id, unsigned int recv_len, unsigned int arg3, int64_t ctx_base, unsigned int trace_target)
{
    int retry_count; int64_t result;
    retry_count = 10;
    do {
        result = IPSEC_SOCK_ProcPipeData(pipe_id, recv_len, arg3, ctx_base, trace_target);  // L26808
        if ((uint32_t)result != 0) break;
        --retry_count;
    } while (retry_count != 0);
    return result;
}
```

## 数据流树状图

### INPUT-1: pipe_id 🔴 TAINTED
```
pipe_id 🔴 TAINTED (外部管道标识符)
└── [L26808] IPSEC_SOCK_ProcPipeData(pipe_id, recv_len, arg3, ctx_base, trace_target)
            → pipe_id 作为第1个参数传入子函数
```

### INPUT-2: recv_len 🔴 TAINTED
```
recv_len 🔴 TAINTED (接收数据长度，对应任务描述的msg_type)
└── [L26808] IPSEC_SOCK_ProcPipeData(pipe_id, recv_len, arg3, ctx_base, trace_target)
            → recv_len 作为第2个参数传入子函数
```

### INPUT-3: trace_target 🔴 TAINTED
```
trace_target 🔴 TAINTED (目标PID，对应任务描述的target_pid)
└── [L26808] IPSEC_SOCK_ProcPipeData(pipe_id, recv_len, arg3, ctx_base, trace_target)
            → trace_target 作为第5个参数传入子函数
```

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| pipe_id | IPSEC_SOCK_ProcPipeData | L26808 | 作为第1实参传入子函数 |
| recv_len | IPSEC_SOCK_ProcPipeData | L26808 | 作为第2实参传入子函数，控制接收长度 |
| trace_target | IPSEC_SOCK_ProcPipeData | L26808 | 作为第5实参传入子函数 |

## 新导入的污点载体

无 — 本函数内无通过输出参数引入的污点载体，所有污点均通过函数参数传入并直接传递给子函数。

## 备注

- ⚠️ DIRECT_SINK 均不在本函数内（L26579 SOCK_RecvMbufEx_fl、L26631/L26734 DbgTracePacket 等在被调用函数内部）
- 本函数只包含一次子函数调用：IPSEC_SOCK_ProcPipeData
- 所有污点参数作为实参原样传递给子函数，无中间处理