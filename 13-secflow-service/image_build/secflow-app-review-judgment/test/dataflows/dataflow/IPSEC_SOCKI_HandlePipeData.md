## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `pipe_id` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `msg_type` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `target_pid` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SOCKI_HandlePipeData

## 函数信息
- 文件: libipsec.c
- 行号: L26824-L26828
- 签名: `int64_t IPSEC_SOCKI_HandlePipeData(int64_t pipe_id, uint16_t msg_type, void* arg3, void* ctx_base)`

## 数据流树状图

### INPUT-1: pipe_id (int64_t) 🔴 TAINTED
├── [L26825] 条件判断 `recv_len == 0 || recv_len == 2` — pipe_id 未参与
├── [L26826] ⚠️ DIRECT_SINK: `(int)pipe_id` — int64_t→int 截断，高32位数据丢失
│   └── [L26826] IPSEC_SOCKI_PipeData((int)pipe_id, recv_len, arg3, ctx_base, trace_target) → 📎 子函数
└── [L26827] return pipe_id → 📌 USED (直接作为函数返回值)

### INPUT-2: msg_type (uint16_t) 🔴 TAINTED
├── [L26825] `recv_len == 0 || recv_len == 2` → 边界检查，recv_len 值用于条件判断
│   └── 未被消费
└── [L26827] IPSEC_SOCKI_PipeData((int)pipe_id, recv_len, arg3, ctx_base, trace_target)
    └── 📎 子函数 (msg_type 作为实参 recv_len)

### INPUT-3: target_pid (unsigned int) 🔴 TAINTED
├── 来源: 派生于 ctx_base 内存读取或 AVL 树遍历，源自外部上下文
└── [L26827] IPSEC_SOCKI_PipeData((int)pipe_id, recv_len, arg3, ctx_base, target_pid)
    └── 📎 子函数 (target_pid 作为实参 trace_target)
        └── [IPSEC_SOCKI_PipeData → IPSEC_SOCK_ProcPipeData]
            └── [L26631] IPSEC_SOCK_DbgTracePacket(ctx_base, trace_cfg, trace_buf, &trace_info0, trace_target)
            └── [L26734] IPSEC_SOCK_DbgTracePacket(ctx_base, trace_cfg, trace_buf, &trace_info0, trace_target)
                ⚠️ DIRECT_SINK: trace_target 控制 packet_len，污点值可导致调试缓冲区拷贝越界

## 新导入的污点对象
无 — 本函数未调用 Recv/Read/Get 等导入外部数据到输出参数

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| pipe_id | return | L26827 | 直接作为函数返回值 |
| pipe_id | DIRECT_SINK | L26826 | int64_t→int 截断，高位数据丢失 |
| target_pid | DIRECT_SINK | L26827→L26631/L26734 | 控制调试缓冲区拷贝长度，潜在越界风险 |