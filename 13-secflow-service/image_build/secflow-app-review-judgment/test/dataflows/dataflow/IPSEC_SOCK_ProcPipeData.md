## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `pipe_id` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `recv_len` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `arg3` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `ctx_base` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `trace_target` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SOCK_ProcPipeData

## 函数信息
- 文件: libipsec.c
- 签名: `IPSEC_SOCK_ProcPipeData(ctx_base, pipe_id, arg3, recv_len, trace_target)`

---

## 污点源总览

| ID | 污点变量 | 类型 | 说明 |
|----|---------|------|------|
| INPUT-1 | pipe_id | uint32_t | 外部管道标识符 🔴 TAINTED |
| INPUT-2 | recv_len | uint32_t | 外部管道消息长度 🔴 TAINTED |
| INPUT-3 | arg3 | (unused) | 连接标识符（死代码） 🔴 TAINTED |
| INPUT-4 | ctx_base | void* | 外部上下文结构指针 🔴 TAINTED |
| INPUT-5 | trace_target | unsigned int | 调试跟踪长度 🔴 TAINTED |

---

## 数据流树状图

### INPUT-1: pipe_id 🔴 TAINTED

```
pipe_id 🔴 TAINTED
└── [L26545] recv_pipe_id = pipe_id → recv_pipe_id 🔴 TAINTED [NEW]
    ├── [L26563] VOS_AVL3_Find(..., &recv_pipe_id, ...) — AVL查找键
    ├── [L26568] SOCK_RecvMbufEx_fl(recv_pipe_id, recv_len, &mbuf, ...) ⚠️ DIRECT_SINK
    │   └── recv_pipe_id 控制从哪个管道读取数据
    └── [L26683] IPSEC_SOCK_SendToSocket(recv_pipe_id, ...) ⚠️ DIRECT_SINK
        └── recv_pipe_id 控制发送目标管道
```

### INPUT-2: recv_len 🔴 TAINTED

```
recv_len 🔴 TAINTED
└── [L26579] SOCK_RecvMbufEx_fl(recv_pipe_id, recv_len, &mbuf, ...) ⚠️ DIRECT_SINK
    └── recv_len 控制从管道读取的字节数上限
    └── mbuf 🔴 TAINTED [NEW CARRIER]
        ├── [L26597] IPSEC_SOCK_CopyDbgTracePacket(ctx_base, vr_entry, mbuf, &trace_len, ...)
        │   └── trace_len 🔴 TAINTED（复制长度受 mbuf 内容控制）
        ├── [L26591] vrid = MBUF_GetVrId() → 🟢 CLEANED（VR ID 来自路由查找，非数据内容）
        ├── [L26610] proto_type = MBUF_GetProtoType(mbuf) → proto_type 🔴 TAINTED
        │   └── [L26613] if (proto_type == 1) → 🔴 TAINTED 用于条件分支选择 AH/ESP 路径
        ├── [L26622] IPSEC_LIBI_HandleOutputPkt(lib_ctx, mbuf, &sa_type) 📎
        ├── [L26627] IPSEC_LIBI_HandleOutputPktV4(lib_ctx, mbuf, &sa_type, lib_ctx) 📎
        ├── [L26662] IPSEC_LIBI_HandleInputPkt(lib_ctx, mbuf, &sa_type, &inbound_flag) 📎
        ├── [L26667] IPSEC_LIBI_HandleInputPktV4(lib_ctx, mbuf, &sa_type, &inbound_flag, lib_ctx) 📎
        ├── [L26637] IPSEC_SOCK_SendToSocket(recv_pipe_id, sock_state, mbuf, ctx_base, vr_entry) 📎
        ├── [L26707] IPSEC_SOCK_Buffer_Packet(cong_node, mbuf, ctx_base) 📎
        ├── [L26726] IPSEC_SOCK_Buffer_Packet(cong_node, mbuf, ctx_base) 📎
        ├── [L26750] common_info = MBUF_GetControlInfo(mbuf, 9) → common_info 🔴 TAINTED [NEW CARRIER]
        │   └── [L26768] IPSEC_SOCK_GetLdmPipeLC(ctx_base, common_info) 📎
        └── [L26777] IPSEC_SOCK_SendToPP6orPP4orLDMPipe(mbuf, ctx_base, sock_state, vr_entry, ldm_pipe) 📎
```

### INPUT-3: arg3 🔴 TAINTED (DEAD_PARAMETER)

```
arg3 🔴 TAINTED
└── ⚠️ DEAD_PARAMETER: 参数声明后从未在函数体中使用
    ├── 未参与任何算术/逻辑运算
    ├── 未作为输出参数传递给子函数
    ├── 未写入任何内存区域
    └── 未参与任何条件判断或数组索引
```

### INPUT-4: ctx_base 🔴 TAINTED

```
ctx_base 🔴 TAINTED
├── [L26572] VOS_AVL3_Find(ctx_base+CTX_CONG_TREE_ROOT_OFF, ..., ctx_base+CTX_CONG_TREE_AUX_OFF) 📎
├── [L26579] SOCK_RecvMbufEx_fl(..., ctx_base+CTX_RECV_CFG_OFF, ...) 📎
├── [L26588] ++RAW_U32((void*)ctx_base, CTX_PKT_STATS_COUNT_OFF) ⚠️ DIRECT_SINK (污点偏移指针写操作)
├── [L26591] VOS_AVL3_Find(ctx_base+276, &vrid, ctx_base+300) 📎
├── [L26604] IPSEC_SOCK_CopyDbgTracePacket(ctx_base, vr_entry, mbuf, &trace_len, &trace_buf) 📎
├── [L26660] IPSEC_SOCK_Buffer_Packet(cong_node, mbuf, ctx_base) 📎
├── [L26684] IPSEC_SOCK_SendToSocket(recv_pipe_id, sock_state, mbuf, ctx_base, vr_entry) 📎
├── [L26702] ++RAW_U32((void*)ctx_base, CTX_SEND_FAIL_COUNT_OFF) ⚠️ DIRECT_SINK
├── [L26708] ++RAW_U32((void*)ctx_base, CTX_SEND_FAIL_COUNT_OFF) ⚠️ DIRECT_SINK
├── [L26748] IPSEC_SOCK_Buffer_Packet(cong_node, mbuf, ctx_base) 📎
├── [L26773] IPSEC_SOCK_GetLdmPipeLC(ctx_base, common_info) 📎
├── [L26777] IPSEC_SOCK_GetLdmPipeMB(ctx_base) 📎
├── [L26780] IPSEC_SOCK_SendToPP6orPP4orLDMPipe(mbuf, ctx_base, sock_state, vr_entry, ldm_pipe) 📎
├── [L26786] ++RAW_U32((void*)ctx_base, CTX_PIPE_SEND_FAIL_COUNT_OFF) ⚠️ DIRECT_SINK
├── [L26792] ++RAW_U32((void*)ctx_base, CTX_PIPE_SEND_FAIL_COUNT_OFF) ⚠️ DIRECT_SINK
└── [多处] RAW_U8/RAW_U32读取 → 条件判断/日志参数 🟡 CONTROLLED
```

### INPUT-5: trace_target 🔴 TAINTED

```
trace_target 🔴 TAINTED
├── [L26631] IPSEC_SOCK_DbgTracePacket(ctx_base, trace_cfg, trace_buf, &trace_info0, trace_target) ⚠️ DIRECT_SINK
│   └── trace_target 作为 packet_len 传入，若内部按此长度从 trace_buf 读取数据则存在越界读风险
└── [L26734] IPSEC_SOCK_DbgTracePacket(ctx_base, trace_cfg, trace_buf, &trace_info0, trace_target) ⚠️ DIRECT_SINK
    └── 同上，Inbound 路径复现
```

---

## 新导入的污点对象 (Newly Introduced Tainted Objects)

| 对象名 | 导入位置 | 导入方式 | 来源污点 |
|--------|---------|---------|---------|
| recv_pipe_id | L26545 | `recv_pipe_id = pipe_id` | pipe_id |
| mbuf | L26579 | `SOCK_RecvMbufEx_fl(..., &mbuf, ...)` | recv_len (控制读取长度) |
| common_info | L26750 | `MBUF_GetControlInfo(mbuf, 9)` | mbuf |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| recv_len | SOCK_RecvMbufEx_fl | L26579 | 控制读取字节数上限，异常大值可能导致缓冲区溢出 |
| recv_pipe_id | SOCK_RecvMbufEx_fl | L26568 | 控制从哪个管道读取数据 |
| recv_pipe_id | IPSEC_SOCK_SendToSocket | L26683 | 控制发送目标管道 |
| ctx_base | RAW_U32 (写操作) | L26588, L26702, L26708, L26786, L26792 | 污点偏移指针写操作 |
| trace_target | IPSEC_SOCK_DbgTracePacket | L26631, L26734 | 作为 packet_len，存在越界读风险 |
| mbuf (new) | 多处子函数调用 | 多个调用点 | 管道读取的污点数据载体 |
| common_info (new) | IPSEC_SOCK_GetLdmPipeLC | L26768 | 从 mbuf 提取的污点控制元数据 |
| arg3 | DEAD_CODE | L26538 | 死代码，参数已声明但从未使用 |

---

## 子函数跟入汇总表

| 函数 | 调用位置 | 接收的污点形参 |
|------|---------|---------------|
| VOS_AVL3_Find | L26563 | recv_pipe_id |
| SOCK_RecvMbufEx_fl | L26568 | recv_pipe_id |
| VOS_AVL3_Find | L26572 | ctx_base+偏移量 |
| SOCK_RecvMbufEx_fl | L26579 | ctx_base+偏移量 |
| VOS_AVL3_Find | L26591 | ctx_base+偏移量 |
| IPSEC_SOCK_CopyDbgTracePacket | L26597 | mbuf |
| IPSEC_SOCK_CopyDbgTracePacket | L26604 | ctx_base |
| IPSEC_LIBI_HandleOutputPkt | L26622 | mbuf |
| IPSEC_LIBI_HandleOutputPktV4 | L26627 | mbuf |
| IPSEC_SOCK_SendToSocket | L26637 | mbuf |
| IPSEC_LIBI_HandleInputPkt | L26662 | mbuf |
| IPSEC_LIBI_HandleInputPktV4 | L26667 | mbuf |
| IPSEC_SOCK_DbgTracePacket | L26631 | trace_target |
| IPSEC_SOCK_SendToSocket | L26683 | recv_pipe_id |
| IPSEC_SOCK_SendToSocket | L26684 | ctx_base |
| IPSEC_SOCK_Buffer_Packet | L26660 | ctx_base |
| IPSEC_SOCK_Buffer_Packet | L26707 | mbuf |
| IPSEC_SOCK_Buffer_Packet | L26726 | mbuf |
| IPSEC_SOCK_Buffer_Packet | L26748 | ctx_base |
| IPSEC_SOCK_GetLdmPipeLC | L26768 | common_info |
| IPSEC_SOCK_GetLdmPipeLC | L26773 | ctx_base |
| IPSEC_SOCK_GetLdmPipeMB | L26777 | ctx_base |
| IPSEC_SOCK_SendToPP6orPP4orLDMPipe | L26777 | mbuf |
| IPSEC_SOCK_SendToPP6orPP4orLDMPipe | L26780 | ctx_base |
| IPSEC_SOCK_DbgTracePacket | L26734 | trace_target |