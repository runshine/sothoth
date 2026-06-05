---
task_id: dfa_257a88db0976488e
status: passed
best_worker: worker-summary
model: local_minimax/MiniMax/MiniMax-M2.5
rounds: 1
duration: 0.0s
cost: $0.0000
---

# 完整数据流分析: IPSEC_SOCKI_PipeMsg

## 分析概览

- **根函数**: `IPSEC_SOCKI_PipeMsg`
- **跟踪函数总数**: 61

## 调用链函数列表

1. `IPSEC_SOCKI_PipeMsg` 📌 根函数
2. `if` └─ 被跟入
3. `IPSEC_SOCKI_HandlePipeData` └─ 被跟入
4. `IPSEC_SOCKI_CloseLDMPipe` └─ 被跟入
5. `IPSEC_MGTI_TimerDelete` └─ 被跟入
6. `IPSEC_SOCKI_PipeData` └─ 被跟入
7. `IPSEC_SOCK_ProcPipeData` └─ 被跟入
8. `IPSEC_SOCK_GetLdmPipeMB` └─ 被跟入
9. `IPSEC_SOCK_GetLdmPipeLC` └─ 被跟入
10. `IPSEC_LIBI_HandleInputPkt` └─ 被跟入
11. `IPSEC_SOCK_Buffer_Packet` └─ 被跟入
12. `IPSEC_LIBI_HandleOutputPktV4` └─ 被跟入
13. `IPSEC_LIBI_HandleOutputPkt` └─ 被跟入
14. `IPSEC_LIBI_HandleInputPktV4` └─ 被跟入
15. `IPSEC_SOCK_DbgTracePacket` └─ 被跟入
16. `IPSEC_SOCK_SendToSocket` └─ 被跟入
17. `IPSEC_PKT_DebugPacket` └─ 被跟入
18. `IPSEC_AH_HandleInputPkt` └─ 被跟入
19. `IPSEC_ESP_HandleInputPkt` └─ 被跟入
20. `CTX_LOG` └─ 被跟入
21. `-` └─ 被跟入
22. `IPSEC_PKT_ParseAndVerifyHdr` └─ 被跟入
23. `IPSEC_PKT_ParseAndVerifyHdrV4` └─ 被跟入
24. `IPSEC_PKT_DebugPacketV4` └─ 被跟入
25. `IPSEC_MakeDbgLibStrSetter` └─ 被跟入
26. `IPSEC_AH_HandleOutputPktV4` └─ 被跟入
27. `__builtin_bswap32` └─ 被跟入
28. `RAW_U8` └─ 被跟入
29. `IPSEC_ESP_HandleOutputPktV4` └─ 被跟入
30. `IPSEC_LIBI_GetManualSa` └─ 被跟入
31. `IPSEC_AH_HandleOutputPkt` └─ 被跟入
32. `RAW_U16` └─ 被跟入
33. `IPSEC_LIB_Ipv6AddrToStr` └─ 被跟入
34. `RAW_U64` └─ 被跟入
35. `IPSEC_Print_File` └─ 被跟入
36. `IPSEC_MakeDbgCompStrSetter` └─ 被跟入
37. `IPSECL_PKT_GetAuthHaslen` └─ 被跟入
38. `IPSEC_SADB_UpdateSaStats` └─ 被跟入
39. `IPSEC_LIB_Ipv4AddrToStr` └─ 被跟入
40. `IPSEC_ESP_HandleOutputPkt` └─ 被跟入
41. `__builtin_bswap16` └─ 被跟入
42. `sub_2F794` └─ 被跟入
43. `IPSEC_LIB_GetLocalTime` └─ 被跟入
44. `IPSEC_SADB_UpdateAuthFailStats` └─ 被跟入
45. `IPSEC_SADB_UpdateInOutPktStats` └─ 被跟入
46. `IPSEC_NvsPrintfStrSetter` └─ 被跟入
47. `IPSEC_SADB_UpdatePktLenStats` └─ 被跟入
48. `IPSEC_ESP_HandleInputPktV4` └─ 被跟入
49. `IPSECL_DBG_AhPktAlgo` └─ 被跟入
50. `IPSEC_AH_HandleInputPktV4` └─ 被跟入
51. `IPSEC_LIB_LOG_IF_ENABLED` └─ 被跟入
52. `IPSEC_SADB_UpdateSaStatsV4` └─ 被跟入
53. `IPSECL_DBG_EspPktAlgo` └─ 被跟入
54. `sub_2FD14` └─ 被跟入
55. `IPSEC_SADB_UpdateInOutPktStatsV4` └─ 被跟入
56. `IPSEC_SADB_UpdateAuthFailStatsV4` └─ 被跟入
57. `def_2FD10` └─ 被跟入
58. `IPSEC_SADB_UpdatePktLenStatsV4` └─ 被跟入
59. `AUTH_UPDATE` └─ 被跟入
60. `IPSECL_DBG_EspPktAlgoV4` └─ 被跟入
61. `AUTH_FINAL` └─ 被跟入

---

## [1/61] IPSEC_SOCKI_PipeMsg  ·  根函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `pipe_id` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `pipe_type` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `msg_type` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SOCKI_PipeMsg

## 函数信息
- 文件: `libipsec.c`
- 行号: L26842-L26890
- 签名: `int IPSEC_SOCKI_PipeMsg(void *ctx, unsigned int pipe_id, unsigned int pipe_type, unsigned int msg_type)`

---

## 污点源总览

| 标识 | 类型 | 来源 | 说明 |
|------|------|------|------|
| `pipe_id` | 🔴 TAINTED | 外部管道ID参数，攻击者可控 | 用于多位置管道匹配检查 |
| `pipe_type` | 🔴 TAINTED | 外部输入参数，来自管道消息处理 | 控制分支走向和LDM树遍历 |
| `msg_type` | 🔴 TAINTED | 外部网络输入，来自管道消息的消息类型字段 | 原样转发至下游处理函数 |

---

## 新导入的污点对象（当前函数内产生）

| 对象名 | 类型 | 导入方式 | 行号 |
|--------|------|----------|------|
| `node` | 🔴 TAINTED | 由 `VOS_AVL3_First`/`VOS_AVL3_Next` 读取，AVL遍历路径受 `pipe_id` 控制 | L26874, L26876, L26879 |
| `ldm_node` | 🔴 TAINTED | 由 `(int *)node` 强制转换得到 | L26873, L26877, L26882 |
| `target_pid` | 🔴 TAINTED | 由 `(unsigned int)pipe_id` 赋值 | L26881 |

---

## 完整传播路径图

### INPUT-1: pipe_id (unsigned int) 🔴 TAINTED
```
├── [L26857] RAW_U32(ctx,152) == (unsigned int)pipe_id → 比较条件
│   └── [L26860] IPSEC_SOCKI_HandlePipeData(pipe_id, msg_type, pipe_type, ctx_base, target_pid)
│       → ⚠️ DIRECT_SINK: pipe_id直接作为第1实参
│
├── [L26865] RAW_U32(ctx,208) == (unsigned int)pipe_id → 比较条件
│
├── [L26868] RAW_U32(ctx,1296) == (unsigned int)pipe_id → 比较条件
│
└── [L26870] pipe_type == 4128768 (LDM分支)
    ├── [L26876] node = VOS_AVL3_First(...) → node 🔴 TAINTED (AVL遍历起点受pipe_id控制)
    │   └── [L26877] ldm_node = (int *)node → ldm_node 🔴 TAINTED
    │       └── [L26879] node = VOS_AVL3_Next(node + 8, ...) → node 🔴 TAINTED
    │           └── [L26880] if (*ldm_node == (int)pipe_id) → ⚠️ DIRECT_SINK: 污点指针解引用
    │           └── [L26881] target_pid = (unsigned int)pipe_id → target_pid 🔴 TAINTED
    │           └── [L26882] ldm_node = (int *)node → ldm_node 更新
    │           └── [L26884] } while (node != 0) → 循环边界由AVL结构决定
    └── [L26887] IPSEC_SOCKI_HandlePipeData(pipe_id, msg_type, pipe_type, ctx_base, target_pid)
        → ⚠️ DIRECT_SINK: pipe_id和target_pid同时作为实参
```

### INPUT-2: pipe_type (unsigned int) 🔴 TAINTED
```
├── [L26845] ctx_base == 0 check — pipe_type 未使用
│
├── [L26859-L26863] PP6管道匹配分支
│   └── [L26863] return IPSEC_SOCKI_HandlePipeData(pipe_id, msg_type, pipe_type, ...)
│       → 📎 CALLEE
│
├── [L26864-L26869] PP4/LDM MB管道检查 — pipe_type 未使用
│
├── [L26870] ⚠️ DIRECT_SINK: 污点分支条件 `pipe_type == 4128768`
│   └── 若条件为真，进入LDM树遍历:
│       ├── [L26872] node = VOS_AVL3_First(...) → node 🔴 TAINTED
│       ├── [L26873] ldm_node = (int*)node → ldm_node 🔴 TAINTED
│       ├── [L26876] *ldm_node → ⚠️ DIRECT_SINK: 污点指针解引用
│       └── [L26877] ldm_node = (int*)node (循环内) → ldm_node 🔴 TAINTED
│
├── [L26880] 默认分支 target_pid = RAW_U32(...) — pipe_type 未使用
│
└── [L26885] return IPSEC_SOCKI_HandlePipeData(pipe_id, msg_type, pipe_type, ...)
    → 📎 CALLEE
```

### INPUT-3: msg_type (unsigned int) 🔴 TAINTED
```
├── [L26858] 直接透传 → IPSEC_SOCKI_HandlePipeData(pipe_id, msg_type, pipe_type, ctx_base, target_pid)
│   → 📎 CALLEE (PP6分支)
│
└── [L26883] 直接透传 → IPSEC_SOCKI_HandlePipeData(pipe_id, msg_type, pipe_type, ctx_base, target_pid)
    → 📎 CALLEE (fallback分支)
    
    ✗ [L26850] CTX_LOG — msg_type 未参与日志输出
    ✗ [L26862] PP4/AVL分支 — msg_type 未被使用
    ✗ [L26874] pipe_type==4128768 分支 — msg_type 未被使用
```

---

## 新引入污点对象的下游传播

### node (🔴 TAINTED) — 由 VOS_AVL3_First/VOS_AVL3_Next 产生
```
├── [L26877] ldm_node = (int *)node → ldm_node 🔴 TAINTED
│   └── [L26879] node = VOS_AVL3_Next(node + 8, ...) → node 更新为TAINTED
└── [L26880] *ldm_node → ⚠️ DIRECT_SINK: 受污点影响的指针解引用
```

### ldm_node (🔴 TAINTED) — 由 (int*)node 转换产生
```
├── [L26876] *ldm_node → ⚠️ DIRECT_SINK: 污点指针解引用
└── [L26877] ldm_node = (int*)node → ldm_node 更新为TAINTED
```

### target_pid (🔴 TAINTED) — 由 (unsigned int)pipe_id 赋值产生
```
└── [L26860/L26887] IPSEC_SOCKI_HandlePipeData(..., target_pid)
    → ⚠️ DIRECT_SINK: target_pid作为实参传入
```

---

## DIRECT_SINK 汇总

| 位置 | 危险操作 | 说明 |
|------|---------|------|
| L26857 | 比较条件 | `RAW_U32(ctx,152) == pipe_id` — 管道ID比对，攻击者可通过污点数据选择匹配目标 |
| L26865 | 比较条件 | `RAW_U32(ctx,208) == pipe_id` — 另一处管道ID检查 |
| L26868 | 比较条件 | `RAW_U32(ctx,1296) == pipe_id` — 第三处管道ID检查 |
| L26870 | 分支条件 | `pipe_type == 4128768` 控制代码执行路径，攻击者可通过污点数据选择是否进入LDM树遍历逻辑 |
| L26874-L26878 | 指针运算+解引用 | 当分支成立时，`ldm_node = (int*)node` 后解引用 `*ldm_node`，在AVL树遍历中产生污点指针解引用 |
| L26880 | 指针解引用 | `*ldm_node == (int)pipe_id` — 受污点影响的指针解引用比较 |
| L26860/L26887 | 实参传递 | `IPSEC_SOCKI_HandlePipeData(pipe_id, ..., target_pid)` — pipe_id和target_pid作为实参 |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `pipe_id` | DIRECT_SINK | L26857, L26865, L26868, L26870 | 多处比较/分支条件，攻击者控制管道匹配 |
| `pipe_id` | CALLEE | L26860, L26887 | 传入IPSEC_SOCKI_HandlePipeData |
| `pipe_type` | DIRECT_SINK | L26870 | 分支条件 `pipe_type == 4128768` |
| `pipe_type` | CALLEE | L26863, L26885 | 传入IPSEC_SOCKI_HandlePipeData |
| `msg_type` | CALLEE | L26860, L26883 | 原样转发至IPSEC_SOCKI_HandlePipeData |
| `node` | DIRECT_SINK | L26880 | 指针解引用 `*ldm_node` |
| `ldm_node` | DIRECT_SINK | L26876, L26880 | 指针解引用 |
| `target_pid` | CALLEE | L26860, L26887 | 作为实参传入下游函数 |

---

## 安全备注

1. **高危分支条件**: `pipe_type == 4128768` 允许攻击者通过污点数据选择是否进入LDM树遍历逻辑
2. **AVL遍历路径**: `VOS_AVL3_First/Next` 遍历起点受污点 `pipe_id` 影响，可能遍历到恶意节点
3. **指针解引用风险**: `(int*)node` 转换后解引用 `*ldm_node`，若node指向非预期内存区域将导致访问违例
4. **攻击者可通过污点数据**:
   - 控制多位置管道ID匹配结果
   - 选择是否进入LDM特定处理分支
   - 影响AVL树遍历路径
   - 操控实参传入下游函数

---

## 接收污点数据的子函数汇总

| 函数 | 调用位置 | 接收的形参 | 来源污点 |
|------|---------|----------|---------|
| `IPSEC_SOCKI_HandlePipeData` | L26860 | `pipe_id`, `msg_type`, `target_pid` | pipe_id, msg_type, target_pid |
| `IPSEC_SOCKI_HandlePipeData` | L26863 | `pipe_type` | pipe_type |
| `IPSEC_SOCKI_HandlePipeData` | L26883 | `msg_type` | msg_type |
| `IPSEC_SOCKI_HandlePipeData` | L26885 | `pipe_type` | pipe_type |
| `IPSEC_SOCKI_HandlePipeData` | L26887 | `pipe_id`, `target_pid` | pipe_id, target_pid |

---

## [2/61] if  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `node` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: if

## 函数信息
- 文件: libipsec.c
- 函数签名: `if` (条件分支处理函数)

## 污点源 (Taint Sources)

| 变量 | 类型 | 来源 | 位置 |
|------|------|------|------|
| node | int64_t | 外部AVL树节点 | L17443, L17476 |
| next_node | int64_t | 由VOS_AVL3_Next派生 | L17445, L17479 |

---

## 新导入的污点对象 (Newly Introduced Tainted Objects)

| 对象 | 类型 | 来源 | 派生位置 | 后续传播 |
|------|------|------|---------|---------|
| next_node | int64_t | VOS_AVL3_Next | L17445 | 赋值给node (L17473) |
| next_node | int64_t | VOS_AVL3_Next | L17479 | 赋值给node (L17499) |

---

## 污点传播路径 (Taint Propagation)

### INPUT-1: node (int64_t) 🔴 TAINTED
```
├── [L17443] node = VOS_AVL3_First(ctx_base + 988, ctx_base + 1012)
│   └── [L17445] next_node = VOS_AVL3_Next(node + 4, ctx_base + 1012) → next_node 🔴 TAINTED
│       ├── [L17449] if (RAW_I16(node, 28) != -1 && RAW_I16(node, 30) != -1) → 条件读取
│       ├── [L17457] if (RAW_I16(node, 28) != -1 && RAW_I16(node, 30) != -1) → 条件读取
│       ├── [L17451] VOS_AVL3_Delete(node+offset) → 📎 见跟入表
│       ├── [L17459] VOS_AVL3_Delete(node+offset) → 📎 见跟入表
│       ├── [L17471] VRP_Free_F(node, ...) → 📌 USED
│       └── [L17473] node = next_node → 赋值传播
│
└── [L17476] node = VOS_AVL3_First(ctx_base + 1032, ctx_base + 1056) → node 🔴 TAINTED
    └── [L17479] next_node = VOS_AVL3_Next(node + 8, ctx_base + 1056) → next_node 🔴 TAINTED
        ├── [L17480] ⚠️ DIRECT_SINK: IPSEC_SOCKI_CloseLDMPipe(ctx_base, node) — 污点作为管道描述符
        ├── [L17482] if (RAW_I16(node, 32) != -1 && RAW_I16(node, 34) != -1) → 条件读取
        ├── [L17490] if (RAW_I16(node, 32) != -1 && RAW_I16(node, 34) != -1) → 条件读取
        ├── [L17484] VOS_AVL3_Delete(node+offset) → 📎 见跟入表
        ├── [L17492] VOS_AVL3_Delete(node+offset) → 📎 见跟入表
        ├── [L17497] VRP_Free_F(node, ...) → 📌 USED
        └── [L17499] node = next_node → 赋值传播
```

### INPUT-2: next_node (int64_t) 🔴 TAINTED
```
├── [L17445] VOS_AVL3_Next(node + 4, ctx_base + 1012) → next_node 🔴 TAINTED
│   └── [L17473] node = next_node → node 🔴 TAINTED (反馈回node)
│
└── [L17479] VOS_AVL3_Next(node + 8, ctx_base + 1056) → next_node 🔴 TAINTED
    └── [L17499] node = next_node → node 🔴 TAINTED (反馈回node)
```

---

## 高危Sink (DIRECT_SINK)

| 位置 | 危险操作 | 说明 |
|------|---------|------|
| L17480 | IPSEC_SOCKI_CloseLDMPipe(ctx_base, node) | 污点node作为管道描述符传递 |
| L17451,L17459 | VOS_AVL3_Delete(node+offset) | node+offset作为指针参数 |
| L17484,L17492 | VOS_AVL3_Delete(node+offset) | node+offset作为指针参数 |
| L17471,L17497 | VRP_Free_F(node, ...) | 污点node作为内存释放对象 |
| L17445,L17479 | VOS_AVL3_Next(node+offset, ...) | offset受污点控制 |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| node | IPSEC_SOCKI_CloseLDMPipe | L17480 | 管道描述符参数 |
| node | VOS_AVL3_Delete | L17451,L17459,L17484,L17492 | AVL树节点删除 |
| node | VRP_Free_F | L17471,L17497 | 内存释放 |
| next_node | node赋值 | L17473,L17499 | 污点反馈传播 |

---

## 跟入子函数表 (Callee Tracking)

| 子函数 | 调用位置 | 接收的形参 | 污点来源 |
|--------|---------|-----------|---------|
| IPSEC_SOCKI_CloseLDMPipe | L17480 | pipe_desc (node) | node |
| VOS_AVL3_Delete | L17451,L17459,L17484,L17492 | node+offset | node |
| VRP_Free_F | L17471,L17497 | node | node |

---

## [3/61] IPSEC_SOCKI_HandlePipeData  ·  被跟入函数

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

---

## [4/61] IPSEC_SOCKI_CloseLDMPipe  ·  被跟入函数

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

---

## [5/61] IPSEC_MGTI_TimerDelete  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `timer_slot` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_MGTI_TimerDelete

## 函数信息
- 文件: libipsec.c
- 签名: `void IPSEC_MGTI_TimerDelete(void *timer_slot)`

## 数据流树状图

### INPUT-1: timer_slot (uint64_t *) 🔴 TAINTED - 外部调用者传入的指针
├── [L18195] if (timer_slot == NULL) → 安全检查
├── [L18196] timer_entry = (uint64_t *)*timer_slot → timer_entry 🔴 TAINTED（新导入对象）
│   ├── [L18197] if (*timer_slot == 0) → 安全检查
│   ├── [L18200] APPTMR_DeleteTimer(..., *timer_entry) ⚠️ DIRECT_SINK
│   │       └── 污点数据直接作为计时器句柄
│   └── [L18202] VRP_Free_F(timer_entry) 📎 见跟入列表
└── [L18204] *timer_slot = 0 → 输出参数写入清洁值

### 新导入的污点对象: timer_entry (uint64_t *)
- 来源: [L18196] 通过解引用 timer_slot 获得
- 追踪:
  - [L18200] 作为参数传入 APPTMR_DeleteTimer → ⚠️ DIRECT_SINK
  - [L18202] 作为参数传入 VRP_Free_F → 📎 见跟入列表

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| timer_slot | APPTMR_DeleteTimer | L18200 | 污点指针作为计时器句柄 |
| timer_entry | APPTMR_DeleteTimer | L18200 | 污点数据直接作为计时器句柄使用 |

## 高危操作
| 操作 | 位置 | 风险描述 |
|------|------|----------|
| APPTMR_DeleteTimer 调用 | L18200 | 污点数据直接作为计时器句柄，可能导致错误的计时器被删除 |
| VRP_Free_F 调用 | L18202 | 污点指针可能被用于释放内存，若值非法可能导致崩溃 |

---

## [6/61] IPSEC_SOCKI_PipeData  ·  被跟入函数

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

---

## [7/61] IPSEC_SOCK_ProcPipeData  ·  被跟入函数

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

---

## [8/61] IPSEC_SOCK_GetLdmPipeMB  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `ctx_base` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SOCK_GetLdmPipeMB

## 函数信息
- 文件: libipsec.c
- 签名: `void* IPSEC_SOCK_GetLdmPipeMB(void* ctx_base)`
- 功能: 从上下文基址获取LDM管道消息缓冲区指针

## 数据流树状图

### INPUT-1: ctx_base (void*) 🔴 TAINTED
├── [L24482] RAW_U32((void*)ctx_base, CTX_LDM_MB_PIPE_OFF) == 0 → 🟢 CLEANED (仅作分支条件，偏移量为编译时常量 1256)
└── [L24484] RAW_U32((void*)ctx_base, CTX_LDM_MB_PIPE_STATE_OFF) != 0 → 🟢 CLEANED (仅作分支条件，偏移量为编译时常量 1260)
    └── [L24486] return ctx_base + CTX_LDM_MB_PIPE_OFF → 🟢 CLEANED (偏移量 CTX_LDM_MB_PIPE_OFF=1256 为编译时常量，非用户数据派生)

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| ctx_base | 字段读取 | L24482 | CTX_LDM_MB_PIPE_OFF(1256) 偏移量编译时常量，仅作分支条件 |
| ctx_base | 字段读取 | L24484 | CTX_LDM_MB_PIPE_STATE_OFF(1260) 偏移量编译时常量，仅作分支条件 |
| ctx_base | 指针运算 | L24486 | 偏移量 1256 为编译时常量，未向返回值传播污点 |

## 新导入的污点对象
无

## 接收此污点的子函数
无

## 总结
`ctx_base` 仅被用于从固定偏移量读取 u32 值作为分支条件判断。偏移量 `CTX_LDM_MB_PIPE_OFF`(1256) 和 `CTX_LDM_MB_PIPE_STATE_OFF`(1260) 均为编译时常量，非用户数据派生，因此污点已清洗(🟢 CLEANED)。

函数返回值 `ctx_base + 1256` 的偏移量为编译时常量，污点未向返回值传播。本函数内无 ⚠️ DIRECT_SINK 操作。

---

## [9/61] IPSEC_SOCK_GetLdmPipeLC  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `common_info` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SOCK_GetLdmPipeLC

## 函数信息
- 文件: libipsec.c
- 签名: `void* IPSEC_SOCK_GetLdmPipeLC(void* ctx_base, void* pid_ptr)`

## 污点源
| 变量 | 类型 | 来源 | 说明 |
|------|------|------|------|
| common_info | void* | MBUF_GetControlInfo(mbuf, 9) | 🔴 TAINTED — 从网络包控制信息中提取的外部输入 |

## 传播路径

### INPUT-1: common_info (void*) 🔴 TAINTED
```
[污点来源]
  MBUF_GetControlInfo(mbuf, 9)
        ↓
[L26773] 传入参数: IPSEC_SOCK_GetLdmPipeLC(ctx_base, common_info)
        ↓
[当前函数: IPSEC_SOCK_GetLdmPipeLC]
        ↓
[L26502] *node != *pid_ptr
        └── *pid_ptr 解引用参与AVL树节点比较 🔴 TAINTED
        ↓
[L26509] *pid_ptr != *candidate
        └── *pid_ptr 在循环中与候选节点比较 🔴 TAINTED
        ↓
[终点] 函数内部使用，无外部传播
```

## 污点终点汇总
| 变量 | 终点 | 位置 | 说明 |
|------|------|------|------|
| common_info (*pid_ptr) | 📌 USED | L26502 | AVL树节点比较运算 |
| common_info (*pid_ptr) | 📌 USED | L26509 | 循环中与候选节点比较 |

## 新导入污点对象
无新对象导入 — common_info 是从外部传入的已有污点载体

## 备注
- 当前函数为污点数据的最终消费者
- common_info 被解引用后参与树结构比较操作
- 无进一步污点传播至其他函数

---

## [10/61] IPSEC_LIBI_HandleInputPkt  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIBI_HandleInputPkt

## 函数信息
- 文件: libipsec.c
- 函数: `IPSEC_LIBI_HandleInputPkt`
- 污点类型: 🔴 TAINTED - 外部网络数据包

---

## 污点源

| 名称 | 类型 | 说明 |
|------|------|------|
| mbuf | mbuf* | 🔴 TAINTED - 外部网络数据包缓冲区 |

---

## 传播路径

```
### INPUT: mbuf (mbuf*) 🔴 TAINTED
│
├── [L11009] receive_if_index = MBUF_GetReceiveIfIndex(mbuf, ...) → receive_if_index 🔴 TAINTED
│   └── 说明: 从mbuf中提取接收接口索引，产生新的污点载体
│   └── 用途: 用于调试/诊断操作（仅控制流，无直接Sink风险）
│
├── [L11027] IPSEC_PKT_ParseAndVerifyHdr(mbuf, lib_ctx, parse_state) 📎
│   └── 参数: mbuf (🔴 TAINTED)
│   └── 说明: 从mbuf中解析并验证IPsec头部
│
├── [L11069] IPSEC_AH_HandleInputPkt(lib_ctx, mbuf, parse_state) 📎
│   └── 参数: mbuf (🔴 TAINTED)
│   └── 说明: 处理AH（认证头）入站数据包
│
└── [L11113] IPSEC_ESP_HandleInputPkt(lib_ctx, mbuf, parse_state) 📎
    └── 参数: mbuf (🔴 TAINTED)
    └── 说明: 处理ESP（封装安全载荷）入站数据包
```

---

## 新增污点载体追踪

| 污点载体 | 来源 | 行号 | 说明 |
|----------|------|------|------|
| receive_if_index | MBUF_GetReceiveIfIndex() | L11009 | 从mbuf提取的接收接口索引 |

**receive_if_index 用途分析**:
- 用于调试/诊断操作
- 仅参与控制流判断
- 无直接 Sink 消费

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf | IPSEC_PKT_ParseAndVerifyHdr | L11027 | 解析IPsec头部 |
| mbuf | IPSEC_AH_HandleInputPkt | L11069 | 处理AH入站数据包 |
| mbuf | IPSEC_ESP_HandleInputPkt | L11113 | 处理ESP入站数据包 |

---

## 调用子函数清单

| 序号 | 函数 | 调用行 | 接收参数 | 性质 |
|------|------|--------|----------|------|
| 1 | IPSEC_PKT_ParseAndVerifyHdr | L11027 | mbuf | 📎 见跟入列表 |
| 2 | IPSEC_AH_HandleInputPkt | L11069 | mbuf | 📎 见跟入列表 |
| 3 | IPSEC_ESP_HandleInputPkt | L11113 | mbuf | 📎 见跟入列表 |

---

## 备注

- **污点类型**: 外部网络输入（不可信数据包）
- **安全边界**: 本函数为IPsec处理入口，需要对mbuf内容进行严格验证
- **传播方向**: mbuf作为核心参数传递至多个处理子函数

---

## [11/61] IPSEC_SOCK_Buffer_Packet  ·  被跟入函数

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

---

## [12/61] IPSEC_LIBI_HandleOutputPktV4  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIBI_HandleOutputPktV4

## 函数信息
- 文件: libipsec.c
- 功能: 处理出站 IPv4 数据包的 IPSec 封装/处理入口函数
- 污点来源: mbuf (外部网络数据包缓冲区，outbound IPv4 packet)

---

## 污点源

| 变量 | 类型 | 说明 |
|------|------|------|
| `mbuf` | struct mbuf* | 🔴 TAINTED — 外部网络数据包缓冲区 (outbound IPv4 packet) |

---

## 新导入的污点对象 (在函数内产生)

| 变量 | 导入方式 | 位置 | 说明 |
|------|---------|------|------|
| `parse_state[]` | `IPSEC_PKT_ParseAndVerifyHdrV4()` 写入 | L11627 | IPv4 头部解析结果 |
| `control_info` | `MBUF_GetControlInfo(mbuf, 10)` 返回 | L11631 | mbuf 关联的控制元数据 |
| `send_if_index` | `MBUF_GetSendIfIndex(mbuf)` 返回 | L11608 | 发送接口索引 |
| `esp_spi` | `__builtin_bswap32(control_info[1])` | L11633 | ESP 安全参数索引 |
| `ah_spi` | `__builtin_bswap32(control_info[0])` | L11634 | AH 安全参数索引 |
| `dst_ipv4` | `__builtin_bswap32(RAW_U32(parse_state, PST_DST4_RAW))` | L11629 | 目的 IPv4 地址 |

---

## 完整数据流树状图

```
mbuf 🔴 TAINTED (外部网络数据包)
├── [L11608] send_if_index = MBUF_GetSendIfIndex(mbuf) → send_if_index 🔴 TAINTED
│   └── [L11609] RAW_U32(parse_state, PST_PKT_KIND) = send_if_index
│       └── parse_state[] 🔴 TAINTED (新导入)
│
├── [L11627] status = IPSEC_PKT_ParseAndVerifyHdrV4(mbuf, lib_ctx, parse_state, stats_ctx)
│   └── parse_state[] 🔴 TAINTED (新导入: output 参数)
│       ├── [L11629] dst_ipv4 = __builtin_bswap32(RAW_U32(parse_state, PST_DST4_RAW))
│       │   └── dst_ipv4 🔴 TAINTED (新导入)
│       └── [L11631] control_info = (uint32_t *)MBUF_GetControlInfo(mbuf, 10)
│           └── control_info 🔴 TAINTED (新导入)
│               ├── [L11633] esp_spi = __builtin_bswap32(control_info[1])
│               │   └── esp_spi 🔴 TAINTED (新导入)
│               ├── [L11634] ah_spi = __builtin_bswap32(control_info[0])
│               │   └── ah_spi 🔴 TAINTED (新导入)
│               └── [L11636] manual_sa = IPSEC_LIBI_GetManualSa(lib_ctx, parse_state, control_info)
│                   └── parse_state 🔴 TAINTED, control_info 🔴 TAINTED
│
├── [L11649] IPSEC_ESP_HandleOutputPktV4(lib_ctx, mbuf, parse_state, stats_ctx)
│   └── mbuf 🔴 TAINTED, parse_state[] 🔴 TAINTED
│
├── [L11690] IPSEC_AH_HandleOutputPktV4(lib_ctx, mbuf, parse_state, stats_ctx)
│   └── mbuf 🔴 TAINTED, parse_state[] 🔴 TAINTED
│
├── [L11723] MBUF_ClearFlag(mbuf, 0x10000000) — flag 操作
├── [L11724] MBUF_SetFlag(mbuf, 0x4000) — flag 操作
├── [L11725] MBUF_SetFlag(mbuf, 0x20000000) — flag 操作
├── [L11726] MBUF_DeleteControlInfo(mbuf, 10) — 删除元数据
│
├── [L11754] fallback: IPSEC_ESP_HandleOutputPktV4(...)
│   └── mbuf 🔴 TAINTED
│
└── [L11775] fallback: IPSEC_PKT_ParseAndVerifyHdrV4(mbuf, ...)
    └── mbuf 🔴 TAINTED
```

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf | 📌 USED | L11649, L11690 | 传递给 ESP/AH 输出处理函数 |
| parse_state[] | 📌 USED | L11649, L11690 | 传递 IPv4 头部解析结果 |
| control_info | ⚠️ DIRECT_SINK | L11631 | 从 mbuf 提取 SPI/端口控制信息 |
| esp_spi | ⚠️ DIRECT_SINK | L11633 | 从被污染的控制数据提取 32-bit ESP SPI |
| ah_spi | ⚠️ DIRECT_SINK | L11634 | 从被污染的控制数据提取 32-bit AH SPI |
| dst_ipv4 | ⚠️ DIRECT_SINK | L11629 | 从被污染的 mbuf 解析数据提取目的地址 |

---

## 直接 Sink 标注

| 行号 | 操作 | 风险描述 |
|------|------|----------|
| L11631 | MBUF_GetControlInfo(mbuf, 10) | CRITICAL: 从 mbuf 提取 SPI/端口控制信息，决定加密/认证算法选择 |
| L11633 | esp_spi = __builtin_bswap32(control_info[1]) | 从被污染的 mbuf 控制数据中提取 32-bit ESP SPI |
| L11634 | ah_spi = __builtin_bswap32(control_info[0]) | 从被污染的 mbuf 控制数据中提取 32-bit AH SPI |
| L11636 | IPSEC_LIBI_GetManualSa(..., parse_state, control_info) | SA 查找使用源自 mbuf 的被污染头部字段和控制信息 |

---

## [13/61] IPSEC_LIBI_HandleOutputPkt  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIBI_HandleOutputPkt

## 函数信息
- 文件: libipsec.c
- 签名: `int IPSEC_LIBI_HandleOutputPkt(libipsec_ctx_t *lib_ctx, struct mbuf *mbuf, ...)`

## 污点源

### INPUT-1: mbuf (struct mbuf*) 🔴 TAINTED
外部网络输入的网络包缓冲区。

| 行号 | 操作 | 结果 | 说明 |
|------|------|------|------|
| L10804 | null check | 无传播 | 仅做空指针检查 |
| L10807 | MBUF_GetSendIfIndex(mbuf) | 🟢 CLEANED | 提取接口索引标量，不含包载荷 |
| L10825 | IPSEC_PKT_ParseAndVerifyHdr(mbuf, lib_ctx, &parse_state) | ⚠️ NEW_OBJECT | 输出参数 `parse_state` 被写入 |
| L10852 | MBUF_GetControlInfo(mbuf, 10) | 🟢 CLEANED | 提取元数据，非包载荷 |
| L10861 | IPSEC_AH_HandleOutputPkt(lib_ctx, mbuf, parse_state) | 📎 子函数 | mbuf 作为参数传入 |
| L10890 | IPSEC_ESP_HandleOutputPkt(lib_ctx, mbuf, parse_state) | 📎 子函数 | mbuf 作为参数传入 |
| L10911-L10913 | MBUF_ClearFlag/SetFlag/DeleteControlInfo(mbuf) | ⚠️ 终态 | mbuf 状态操作终态 |

## 新引入的污点对象

### parse_state (输出参数) 🔴 TAINTED
- **引入方式**: `IPSEC_PKT_ParseAndVerifyHdr(mbuf, lib_ctx, &parse_state)` 在 L10825 写入
- **污点来源**: mbuf 网络包头中的字段解析
- **字段映射**:
  - `parse_state[12..15]` (PST_SPI) ← mbuf 头部的 SPI 字段
  - `parse_state[36..51]` (PST_DST6) ← mbuf 目标地址字段

| 行号 | 操作 | 结果 | 说明 |
|------|------|------|------|
| L10861 | IPSEC_AH_HandleOutputPkt(lib_ctx, mbuf, parse_state) | 📎 子函数 | parse_state 作为参数传入 |
| L10890 | IPSEC_ESP_HandleOutputPkt(lib_ctx, mbuf, parse_state) | 📎 子函数 | parse_state 作为参数传入 |

## 数据流树状图

```
### INPUT-1: mbuf (struct mbuf*) 🔴 TAINTED
├── [L10804] null check → 无传播
├── [L10807] MBUF_GetSendIfIndex(mbuf) → send_if_index 🟢 CLEANED
├── [L10825] IPSEC_PKT_ParseAndVerifyHdr(mbuf, lib_ctx, &parse_state)
│   └── parse_state 🔴 TAINTED ⚠️ NEW_OBJECT
│       ├── [L10861] IPSEC_AH_HandleOutputPkt(lib_ctx, mbuf, parse_state) → 📎 子函数
│       └── [L10890] IPSEC_ESP_HandleOutputPkt(lib_ctx, mbuf, parse_state) → 📎 子函数
├── [L10861] IPSEC_AH_HandleOutputPkt(lib_ctx, mbuf, parse_state) → 📎 子函数
├── [L10890] IPSEC_ESP_HandleOutputPkt(lib_ctx, mbuf, parse_state) → 📎 子函数
└── [L10911-L10913] MBUF_* operations → ⚠️ 终态

### NEW_OBJECT: parse_state 🔴 TAINTED
├── [L10861] IPSEC_AH_HandleOutputPkt(lib_ctx, mbuf, parse_state)
└── [L10890] IPSEC_ESP_HandleOutputPkt(lib_ctx, mbuf, parse_state)
```

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf | IPSEC_PKT_ParseAndVerifyHdr | L10825 | mbuf 作为入参，解析头字段 |
| mbuf | IPSEC_AH_HandleOutputPkt | L10861 | mbuf 作为入参 |
| mbuf | IPSEC_ESP_HandleOutputPkt | L10890 | mbuf 作为入参 |
| mbuf | MBUF_* operations | L10911-L10913 | mbuf 状态操作终态 |
| parse_state | IPSEC_AH_HandleOutputPkt | L10861 | parse_state 作为入参 |
| parse_state | IPSEC_ESP_HandleOutputPkt | L10890 | parse_state 作为入参 |

---

## [14/61] IPSEC_LIBI_HandleInputPktV4  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIBI_HandleInputPktV4

## 函数信息
- 文件: libipsec.c
- 行号: L11800-L11870
- 签名: `void IPSEC_LIBI_HandleInputPktV4(void* lib_ctx, int64_t mbuf, int* proto_out, void* stats_ctx)`

## 污点源

| 参数 | 类型 | 状态 | 说明 |
|------|------|------|------|
| mbuf | int64_t | 🔴 TAINTED | 外部网络输入，承载原始IPv4/IPSec数据包 |

## 新导入的污点对象

| 对象 | 类型 | 引入位置 | 说明 |
|------|------|---------|------|
| parse_state | uint8_t[64] | L11827 | 由 IPSEC_PKT_ParseAndVerifyHdrV4 调用 MBUF_MakeMemoryContinuous_fl 读取mbuf数据后写入，64字节全部从网络数据中提取（版本、协议、IP头长度、总长度、源/目的IP、SPI、端口等） |

## 数据流树状图

### INPUT-1: mbuf (int64_t) 🔴 TAINTED
├── [L11809] MBUF_GetReceiveIfIndex(mbuf, ...) → mbuf 保持污点 🔴 TAINTED
├── [L11827] IPSEC_PKT_ParseAndVerifyHdrV4(mbuf, lib_ctx, parse_state, stats_ctx) → **parse_state 成为新污点载体** 🔴 TAINTED
│   ├── [L11829] RAW_U32(parse_state, PST_DST4_RAW) → dst_ipv4 🔴 TAINTED
│   │   └── [L11838] IPSEC_PKT_DebugPacketV4(..., dst_ipv4, ...) → 🟡 EXPORT（调试函数）
│   ├── [L11830] IPSEC_LIBI_GetManualSa(lib_ctx, parse_state, 0) → 📎 见跟入列表
│   ├── [L11831] RAW_U8(parse_state, PST_PROTO) → 条件判断
│   ├── [L11838] RAW_U8(parse_state, PST_PROTO) → 条件判断
│   ├── [L11840] IPSEC_AH_HandleInputPktV4(lib_ctx, mbuf, parse_state, stats_ctx) → 📎 见跟入列表
│   │   └── ⚠️ DIRECT_SINK: 子函数内 parse_state[0..3]（packet_info[0]）控制 MBUF_MakeMemoryContinuous_fl 的读取偏移/长度；parse_state[4]（packet_info[4]）控制 VRP_Malloc_F 分配大小和 MBUF_CopyDataFromMBufToBuffer 拷贝长度
│   └── [L11868] IPSEC_ESP_HandleInputPktV4(lib_ctx, mbuf, parse_state, stats_ctx) → 📎 见跟入列表
│       └── ⚠️ DIRECT_SINK: 子函数内 parse_state[0..3]（packet_info[0]）控制 MBUF_MakeMemoryContinuous_fl 的读取偏移；parse_state[4]（packet_info[4]）控制 payload_len 计算，进而影响 ESP 载荷处理
└── [L11840] *proto_out = 51 → 🟢 已清洗（常量赋值）
    [L11868] *proto_out = 50 → 🟢 已清洗（常量赋值）

### parse_state 🔴 TAINTED（由mbuf导出）
├── [L11829] RAW_U32(parse_state, PST_DST4_RAW) → dst_ipv4 🔴 TAINTED
│   └── [L11838] IPSEC_PKT_DebugPacketV4(..., dst_ipv4, ...) → 🟡 EXPORT（调试函数）
├── [L11830] IPSEC_LIBI_GetManualSa(lib_ctx, parse_state, 0) → 📎 见跟入列表
├── [L11831/L11838] RAW_U8(parse_state, PST_PROTO) → 条件判断，无新污点变量
├── [L11840] IPSEC_AH_HandleInputPktV4(mbuf, parse_state, ...) → 📎 见跟入列表
│   └── ⚠️ DIRECT_SINK: 子函数内 parse_state[0..3] 控制 mbuf 内存连续化范围；parse_state[4] 控制堆内存分配和缓冲区拷贝大小
└── [L11868] IPSEC_ESP_HandleInputPktV4(mbuf, parse_state, ...) → 📎 见跟入列表
    └── ⚠️ DIRECT_SINK: 子函数内 parse_state[0..3] 控制 mbuf 内存连续化偏移；parse_state[4] 影响 payload_len 计算

## 污点终点汇总

| 脏数据 | 终点类型 | 位置 | 说明 |
|--------|---------|------|------|
| mbuf | 📎 CALLEE | L11827 | 传入 IPSEC_PKT_ParseAndVerifyHdrV4 解析并生成 parse_state |
| mbuf | 📎 CALLEE | L11840 | 传入 IPSEC_AH_HandleInputPktV4 处理AH协议包 |
| mbuf | 📎 CALLEE | L11868 | 传入 IPSEC_ESP_HandleInputPktV4 处理ESP协议包 |
| parse_state | 📎 CALLEE | L11830 | 传入 IPSEC_LIBI_GetManualSa 获取SA条目，SPI字段来自mbuf |
| parse_state | 📎 CALLEE | L11840 | 传入 IPSEC_AH_HandleInputPktV4，控制内存访问和分配大小 |
| parse_state | 📎 CALLEE | L11868 | 传入 IPSEC_ESP_HandleInputPktV4，控制内存访问和payload长度 |
| dst_ipv4 | 🟡 EXPORT | L11838 | 传入调试函数 IPSEC_PKT_DebugPacketV4 |
| *proto_out | 🟢 CLEANED | L11840/L11868 | 已通过常量赋值(51/50)清洗 |

## 高危模式

| 污点字段 | 高危模式 | 说明 |
|---------|---------|------|
| parse_state[0..3] | ⚠️ DIRECT_SINK | 控制 mbuf 内存连续化操作的读取偏移和长度，可能导致越界读取 |
| parse_state[4] | ⚠️ DIRECT_SINK | 控制堆内存分配大小和缓冲区拷贝长度，可能导致堆溢出或缓冲区越界 |

---

## [15/61] IPSEC_SOCK_DbgTracePacket  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `trace_target` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SOCK_DbgTracePacket

## 函数信息
- 文件: libipsec.c
- 签名: `void IPSEC_SOCK_DbgTracePacket(...)`

## 污点源
| 参数 | 类型 | 状态 |
|------|------|------|
| trace_target | - | 🔴 TAINTED |

## 新导入的污点对象
| 对象 | 导入方式 | 说明 |
|------|----------|------|
| 无新导入对象 | - | - |

## 传播路径

### trace_target 🔴 TAINTED
├── [L23598] packet_len → trace_record.word0 🔴 TAINTED
│   └── trace_record.word0 = ((uint64_t)packet_len << 32) | RAW_U32((void *)ctx_base, 4)
├── [L23598] SSP_ProtocolPacketTrace(trace_handle, &trace_record, ...) → 🟡 EXPORT
│   └── 传入 trace_record（含污点 packet_len 构造的 word0）
└── [L23598] packet_buf → SSP_ProtocolPacketTrace(..., packet_buf) → 🟡 EXPORT
    └── 传入 packet_buf（污点缓冲区）

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| trace_target | SSP_ProtocolPacketTrace | L23598 | packet_len 作为实参传入 |
| trace_target | SSP_ProtocolPacketTrace | L23598 | trace_record 含污点 packet_len 构造的 word0 |
| trace_target | SSP_ProtocolPacketTrace | L23598 | packet_buf 作为污点缓冲区传入 |

## 跟入表格
| 子函数 | 调用位置 | 接收的污点形参 |
|--------|----------|----------------|
| SSP_ProtocolPacketTrace | L23598 | trace_record, packet_len, packet_buf |

---

## [16/61] IPSEC_SOCK_SendToSocket  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SOCK_SendToSocket

## 函数信息
- 文件: libipsec.c
- 签名: `void IPSEC_SOCK_SendToSocket(int aSocket, struct mbuf *ambuf, int aFlags)`

## 污点源
| 参数 | 类型 | 状态 |
|------|------|------|
| mbuf | struct mbuf* | 🔴 TAINTED - 外部网络输入，socket mbuf 包含从网络接收的分组数据 |

## 传播路径

### mbuf 🔴 TAINTED
```
├── [L24685-24688] mbuf == 0 → 条件判断，无传播
├── [L24752] SOCK_MBufForwardTokenAlloc_fl(mbuf, ...) → 句柄传递，不提取载荷
├── [L24795] base_ctl = MBUF_GetControlInfo(mbuf, 0) → base_ctl 🔴 TAINTED
│   └── [L24827-24830] base_ctl值拷贝到 ctl_blob → ctl_blob 🔴 TAINTED
├── [L24860] ip_ctl = MBUF_GetControlInfo(mbuf, 8) → ip_ctl 🔴 TAINTED（新载体）
│   ├── [L24864] IPSEC_MBUF_GetIPFlag6(ctl_blob+4, ip_ctl) → ctl_blob 🔴 TAINTED
│   ├── [L24874] memcpy_s(ctl_blob+36, 16, ip_ctl+16, 16) ⚠️ DIRECT_SINK
│   │   └── 污点IP字段（来自mbuf）复制到栈缓冲区，无边界校验
│   ├── [L24878] memcpy_s(ctl_blob+20, 16, ip_ctl, 16) ⚠️ DIRECT_SINK
│   │   └── 源/目的IP从污点ip_ctl复制到固定大小栈缓冲区
│   └── [L24885-24893] RAW_U16(ip_ctl, 32/34) → ctl_blob[52/54] 🔴 TAINTED
│       └── 端口号（污点）写入栈缓冲区
├── [L24902] IPSEC_SOCK_CopyDbgTracePacket(..., mbuf, &trace_len, &trace_buf) → trace_buf 🔴 TAINTED（新载体）
│   └── mbuf分组数据复制到trace_buf
│       └── [L24912] IPSEC_SOCK_DbgTracePacket(ctx_base, ctl_blob, trace_buf, ...) → trace_buf传入调试函数
├── [L24936] ip_ctl = MBUF_GetControlInfo(mbuf, 2) → ip_ctl 🔴 TAINTED（覆盖）
│   └── [L24940] IPSEC_MBUF_GetIPFlag(ctl_blob+4, ip_ctl) → ctl_blob 🔴 TAINTED
│   └── [L24947-24950] RAW_U16/RAW_U32(ip_ctl, ...) → ctl_blob[...] 🔴 TAINTED
├── [L24952] IPSEC_SOCK_CopyDbgTracePacket(..., mbuf, ...) → trace_buf 🔴 TAINTED
├── [L24974] SOCK_SetMbufCtlInfoEx_fl(mbuf, ctl_blob, ...) → mbuf携带ctl_blob写入
└── [L24985] MBUF_Send_fl(..., mbuf, ...) → 📌 USED（最终发送mbuf到socket）
```

## 新导入的污点对象

| 变量名 | 引入位置 | 来源 | 说明 |
|--------|---------|------|------|
| base_ctl | L24795 | MBUF_GetControlInfo(mbuf, 0) | 控制信息提取 |
| ip_ctl | L24860 | MBUF_GetControlInfo(mbuf, 8) | IPv6控制信息 |
| ip_ctl | L24936 | MBUF_GetControlInfo(mbuf, 2) | IPv4控制信息（覆盖） |
| ctl_blob | L24827-24893 | ip_ctl/base_ctl数据写入 | 栈缓冲区84字节，承载污点IP/端口字段 |
| trace_buf | L24902/L24952 | IPSEC_SOCK_CopyDbgTracePacket输出 | 调试跟踪缓冲区，承载mbuf分组数据 |

## 高危操作汇总

| 类型 | 位置 | 说明 |
|------|------|------|
| ⚠️ DIRECT_SINK | L24874 | memcpy_s 目标指针和大小与污点数据相关，IP字段复制到栈缓冲区 |
| ⚠️ DIRECT_SINK | L24878 | memcpy_s 从污点ip_ctl复制源/目的IP到固定大小栈缓冲区 |
| 📌 USED | L24985 | MBUF_Send_fl 将污点mbuf发送到socket |

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf | MBUF_Send_fl | L24985 | 最终发送污点数据到socket |
| ctl_blob | SOCK_SetMbufCtlInfoEx_fl | L24974 | 控制信息写入mbuf |
| trace_buf | IPSEC_SOCK_DbgTracePacket | L24912 | 调试跟踪函数消费 |

## 子函数跟入列表

| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| MBUF_GetControlInfo | L24795 | mbuf |
| MBUF_GetControlInfo | L24860 | mbuf |
| MBUF_GetControlInfo | L24936 | mbuf |
| SOCK_MBufForwardTokenAlloc_fl | L24752 | mbuf |
| IPSEC_SOCK_CopyDbgTracePacket | L24902 | mbuf |
| IPSEC_SOCK_CopyDbgTracePacket | L24952 | mbuf |
| IPSEC_SOCK_DbgTracePacket | L24912 | trace_buf |
| SOCK_SetMbufCtlInfoEx_fl | L24974 | mbuf, ctl_blob |
| MBUF_Send_fl | L24985 | mbuf |

---

## [17/61] IPSEC_PKT_DebugPacket  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `receive_if_index` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_PKT_DebugPacket

## 函数信息
- 文件: `core/ipsec/libipsec.c`
- 函数: `IPSEC_PKT_DebugPacket`
- 行号: L10240–L10275
- 签名: `int64_t IPSEC_PKT_DebugPacket(int64_t a1, int64_t a2, int64_t a3, int64_t a4, int64_t a5, uint32_t packet_kind)`

## 数据流树状图

### INPUT-1: packet_kind (uint32_t) 🔴 TAINTED
来源: 调用者 `IPSEC_LIBI_HandleInputPkt` 传入，值来自 `MBUF_GetReceiveIfIndex(mbuf, ...)` 提取的网络包接收接口索引（L11012处），经 `receive_if_index` 变量直接传参

```
packet_kind 🔴 TAINTED
└── [L10257] kind_filter != (uint32_t)packet_kind — 仅参与 uint32_t 数值比较，无 memcpy/sprintf/数组索引/指针运算
```

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| packet_kind | USED | L10257 | 与 kind_filter 的 uint32_t 数值比较，用于过滤调试日志输出条件判断 |

## 安全备注
- `packet_kind` 仅参与 uint32_t 数值比较，**未检测到 DIRECT_SINK**
- 无 memcpy/sprintf/数组索引/指针运算等危险操作
- 污点数据在函数内部未传播至其他变量或子函数调用

---

## [18/61] IPSEC_AH_HandleInputPkt  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_AH_HandleInputPkt

## 函数信息
- 文件: libipsec.c
- 函数: IPSEC_AH_HandleInputPkt
- 污点源: mbuf_base (外部网络mbuf数据包缓冲区)

## 污点源
- `mbuf_base` (int64_t) 🔴 TAINTED — 外部网络mbuf数据包缓冲区

## 传播路径

### mbuf_base 🔴 TAINTED (外部网络输入)
```
├── [L5638] packet_copy = MBUF_CopyDataFromMBufToBuffer(mbuf_base, 0, packet_info[0], packet_copy)
│   ├── [L5653] first_byte = *(uint8_t*)packet_copy
│   └── [L5660-5662] 算法处理packet_copy
│
├── [L5682] 循环处理payload chunks
│   ├── [L5682] chunk_base = MBUF_MakeMemoryContinuous_fl(mbuf_base, copy_offset, chunk_len, ...)
│   │   └── [L5719] memcpy_s((uint8_t*)payload_copy+copied_len, chunk_len, chunk_base, chunk_len) ⚠️ DIRECT_SINK
│   └── [L5726] payload_copy 累积污点数据 🔴 TAINTED (新导入对象)
│
├── [L5698] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf_base, 0, packet_info[0], ...) 🔴 TAINTED (新导入对象)
│   ├── [L5684] RAW_U8((void*)ip_header, packet_info[1]) = ah_header[0] ⚠️ DIRECT_SINK (污点偏移写入)
│   └── [L5758] 修改协议字段
│
├── [L5710] ah_header = MBUF_MakeMemoryContinuous_fl(mbuf_base, packet_info[0], packet_info[4]-packet_info[0], ...) 🔴 TAINTED (新导入对象)
│   ├── [L5712] ah_spi_network = __builtin_bswap32(*(uint32_t*)(ah_header+4))
│   ├── [L5714] sa_lookup_key = ah_spi_network
│   ├── [L5716] sa_entry = VOS_AVL3_Find(..., &sa_lookup_key, ...) 📎 见跟入列表
│   ├── [L5729] next_header = ah_header[0]
│   └── [L5736] VOS_MemCmp(computed_auth, ah_header+12, auth_hash_len) 📎 见跟入列表
│
├── [L5764] MBUF_CutPart_fl(mbuf_base, packet_info[0], auth_hash_len+12, ...)
├── [L5775] MBUF_CreateControlInfo_fl(mbuf_base, 10, 8, ...)
├── [L5789] MBUF_GetControlInfo(mbuf_base, 10)
└── [L5791] MBUF_SetFlag(mbuf_base, 0x10000000)
```

## 新导入的污点对象 (在函数内从mbuf导出)
| 对象名 | 类型 | 导入方式 | 位置 |
|--------|------|----------|------|
| ip_header | void* | MBUF_MakeMemoryContinuous_fl(mbuf_base, ...) | L5698 |
| ah_header | void* | MBUF_MakeMemoryContinuous_fl(mbuf_base, ...) | L5710 |
| packet_copy | void* | MBUF_CopyDataFromMBufToBuffer(mbuf_base, ...) | L5638 |
| chunk_base | void* | MBUF_MakeMemoryContinuous_fl(mbuf_base, ...) | L5682 |
| payload_copy | void* | 循环中memcpy_s累积写入 | L5726 |
| ah_spi_network | uint32_t | 从ah_header+4提取 | L5712 |
| sa_lookup_key | uint32_t | 从ah_spi_network赋值 | L5714 |

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf_base | MBUF_CopyDataFromMBufToBuffer | L5638 | 提取packet数据 |
| mbuf_base | MBUF_MakeMemoryContinuous_fl | L5682 | 循环提取payload chunks |
| mbuf_base | MBUF_MakeMemoryContinuous_fl | L5698 | 提取IP头 |
| mbuf_base | MBUF_MakeMemoryContinuous_fl | L5710 | 提取AH头 |
| mbuf_base | MBUF_CutPart_fl | L5764 | 裁剪数据包 |
| chunk_base/payload_copy | memcpy_s | L5719 | ⚠️ DIRECT_SINK: 复制大小由污点控制 |
| ip_header/packet_info[1] | RAW_U8写入 | L5684 | ⚠️ DIRECT_SINK: 写入偏移由污点控制 |
| ah_header+12 | VOS_MemCmp | L5736 | 验证认证数据 |
| ah_spi_network | VOS_AVL3_Find | L5716 | SA查找 |

## 高危操作 (DIRECT_SINK)
- **L5719**: `memcpy_s((uint8_t*)payload_copy+copied_len, chunk_len, chunk_base, chunk_len)` 
  - 污点指针chunk_base和大小chunk_len控制复制操作
- **L5684**: `RAW_U8((void*)ip_header, packet_info[1]) = ah_header[0]` 
  - 污点偏移packet_info[1]用于写入IP头字段

---

## [19/61] IPSEC_ESP_HandleInputPkt  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_ESP_HandleInputPkt

## 函数信息
- 文件: libipsec.c
- 签名: `IPSEC_ESP_HandleInputPkt`

## 污点源
- **mbuf** 🔴 TAINTED — 外部网络输入,ESP加密数据包

## 污点传播路径

### INPUT-1: mbuf 🔴 TAINTED
```
├── [L9392] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...)
│   └── ip_header 🔴 TAINTED (IP头视图)
│       └── [L3686] ip_header[1] = next_header (外层IP头协议号) → 📌 USED
├── [L9409] esp_header = MBUF_MakeMemoryContinuous_fl(mbuf, *packet_info, 24, ...)
│   └── esp_header 🔴 TAINTED (ESP头视图)
│       └── [L9438] esp_header[0] → sa_lookup_key 🔴 TAINTED
│           └── [L9446] VOS_AVL3_Find(..., &sa_lookup_key, ...) — SA查找
├── [L9501] MBUF_CopyDataFromMBufToBuffer(mbuf, ..., received_auth)
│   └── 复制认证标签到 received_auth (本地变量)
├── [L9535] chunk = MBUF_MakeMemoryContinuous_fl(mbuf, chunk_offset, chunk_len, ...)
│   └── chunk 🔴 TAINTED (认证区域分片视图)
│       └── [L9564] AUTH_UPDATE(..., chunk, chunk_len)
├── [L9670] MBUF_CopyDataFromMBufToBuffer(mbuf, ..., esp_tail_block)
│   └── esp_tail_block 🔴 TAINTED (加密尾部数据) ← 【新引入污点对象】
│       ├── [L9685] pad_length = esp_tail_block[enc_block_size - 2] 🔴 TAINTED
│       ├── [L9686] next_header = esp_tail_block[enc_block_size - 1] 🔴 TAINTED
│       ├── [L9688] packet_info[29] = pad_length
│       ├── [L9689] packet_info[32] = next_header
│       └── ⚠️ DIRECT_SINK: MBUF_CutTail_fl(mbuf, pad_length+2+auth_hash_len, ...)
│           └── 切割大小参数来源于 esp_tail_block
└── [L9677] IPSEC_ESP_Decryption(mbuf, packet_info, sa_entry, tail_block_ref)
    └── mbuf (解密后) 🔴 TAINTED (原位解密) ← 【新引入污点对象】
        ├── [L9706] MBUF_CutTail_fl(mbuf, ...)
        ├── [L9719] MBUF_CutPart_fl(mbuf, ...)
        ├── [L9741] MBUF_CreateControlInfo_fl(mbuf, ...)
        └── [L9745] MBUF_GetControlInfo(mbuf, ...)
```

### INPUT-2: esp_tail_block 🔴 TAINTED (新引入)
```
├── [L9685] pad_length = esp_tail_block[enc_block_size - 2] 🔴 TAINTED
│   └── ⚠️ DIRECT_SINK: 数组下标依赖 enc_block_size 偏移量
├── [L9686] next_header = esp_tail_block[enc_block_size - 1] 🔴 TAINTED
├── [L9688] packet_info[29] = pad_length
├── [L9689] packet_info[32] = next_header
└── ⚠️ DIRECT_SINK: MBUF_CutTail_fl(mbuf, pad_length+2+auth_hash_len, ...)
    └── 切割大小参数受 esp_tail_block 控制
```

### INPUT-3: mbuf (解密后) 🔴 TAINTED (新引入)
```
├── [L9706] MBUF_CutTail_fl(mbuf, ...) → 去除解密尾部
├── [L9719] MBUF_CutPart_fl(mbuf, ...) → 去除ESP头部
├── [L9741] MBUF_CreateControlInfo_fl(mbuf, ...) → 创建控制信息
└── [L9745] MBUF_GetControlInfo(mbuf, ...) → 提取控制信息
```

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf | ip_header[1]=next_header | L3686 | 外层IP头协议号写入 |
| mbuf | MBUF_CutTail_fl (切割大小) | L9685附近 | pad_length参数受esp_tail_block控制 |
| esp_tail_block | 数组访问 | L9685-9686 | 污点数据作为数组下标偏移 |
| mbuf (解密后) | MBUF_CutTail_fl | L9706 | 去除解密尾部 |
| mbuf (解密后) | MBUF_CutPart_fl | L9719 | 去除ESP头部 |
| mbuf (解密后) | MBUF_CreateControlInfo_fl | L9741 | 创建控制信息 |
| mbuf (解密后) | MBUF_GetControlInfo | L9745 | 提取控制信息 |

## 特殊标记
- ⚠️ DIRECT_SINK: MBUF_CutTail_fl 的切割大小参数来自 esp_tail_block，pad_length 由污点数据控制
- ⚠️ DIRECT_SINK: esp_tail_block[enc_block_size-2/1] 数组下标依赖固定偏移，可能越界

---

## [20/61] CTX_LOG  ·  被跟入函数

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

---

## [21/61] -  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `说明:` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: `-` (合并函数)

## 函数信息
- 文件: libipsec.c
- 签名: 合并阶段 - 整合所有子函数污点分析结果

## 数据流树状图

### 来自: IPSEC_SOCK_ProcPipeData (core/ipsec/libipsec.c, L26538-L26801)

#### INPUT-A: recv_len (unsigned int) 🔴 TAINTED
├── [L26579] SOCK_RecvMbufEx_fl(recv_pipe_id, recv_len, &mbuf, ...)
│   └── mbuf 🔴 TAINTED (网络数据包载体，新污点载体)
│       ├── [L26610] MBUF_GetVrId() → vrid 🔴 TAINTED
│       ├── [L26619] IPSEC_SOCK_CopyDbgTracePacket(ctx_base, vr_entry, mbuf, &trace_len, &trace_buf)
│       │   └── trace_buf 🔴 TAINTED
│       ├── [L26630] MBUF_GetProtoType(mbuf) → proto_type 🔴 TAINTED
│       ├── [L26636] lib_ctx = RAW_U64(vr_entry, VR_LIB_CTX_OFF) → lib_ctx 🔴 TAINTED
│       ├── [L26637] IPSEC_LIBI_HandleOutputPkt(lib_ctx, mbuf, &sa_type)
│       │   └── sa_type 🔴 TAINTED
│       ├── [L26642] IPSEC_LIBI_HandleOutputPktV4(lib_ctx, mbuf, &sa_type, lib_ctx)
│       ├── [L26655] IPSEC_SOCK_Buffer_Packet(cong_node, mbuf, ctx_base)
│       ├── [L26656] RAW_U32(trace_cfg, 4) = trace_len → ⚠️ DIRECT_SINK
│       ├── [L26660] IPSEC_SOCK_SendToSocket(recv_pipe_id, sock_state, mbuf, ctx_base, vr_entry)
│       ├── [L26677] MBUF_GetControlInfo(mbuf, 9) → common_info 🔴 TAINTED (新污点载体)
│       │   └── [L26735] IPSEC_SOCK_GetLdmPipeLC(ctx_base, common_info)
│       ├── [L26693] IPSEC_LIBI_HandleInputPkt(lib_ctx, mbuf, &sa_type, &inbound_flag)
│       │   └── inbound_flag 🔴 TAINTED
│       ├── [L26698] IPSEC_LIBI_HandleInputPktV4(lib_ctx, mbuf, &sa_type, inbound_flag, lib_ctx)
│       ├── [L26710] RAW_U32(trace_cfg, 4) = trace_len → ⚠️ DIRECT_SINK
│       ├── [L26726] IPSEC_SOCK_Buffer_Packet(cong_node, mbuf, ctx_base)
│       └── [L26747] IPSEC_SOCK_SendToPP6orPP4orLDMPipe(mbuf, ctx_base, sock_state, vr_entry, ldm_pipe)

## 高危操作汇总 (DIRECT_SINK)

| 位置 | 操作 | 风险 |
|------|------|------|
| L26579 | SOCK_RecvMbufEx_fl(recv_len, &mbuf, ...) | recv_len 控制接收缓冲区大小 |
| L26656 | RAW_U32(trace_cfg, 4) = trace_len | 污点长度写入固定缓冲区偏移 |
| L26710 | RAW_U32(trace_cfg, 4) = trace_len | 污点长度写入固定缓冲区偏移 |

## 污点终点汇总

| 污点数据 | 终点 | 位置 | 说明 |
|---------|------|------|------|
| recv_len | SOCK_RecvMbufEx_fl | L26579 | 控制外部数据接收大小 |
| mbuf | IPSEC_LIBI_HandleOutputPkt/InputPkt | L26637/26693 | 网络数据包处理 |
| mbuf | IPSEC_SOCK_SendToSocket | L26660 | 发送到 socket |
| mbuf | IPSEC_SOCK_SendToPP6orPP4orLDMPipe | L26747 | 最终发送到管道 |
| trace_len | RAW_U32(trace_cfg, 4) | L26656/26710 | 污点长度写入调试配置 |
| common_info | IPSEC_SOCK_GetLdmPipeLC | L26735 | 用于 LDM 管道查找 |
| sa_type | 输出参数 | L26637/26693 | SA 类型信息传递 |
| inbound_flag | 输出参数 | L26693 | 入站标志传递 |

---

## [22/61] IPSEC_PKT_ParseAndVerifyHdr  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_PKT_ParseAndVerifyHdr

## 函数信息
- 文件: `libipsec.c`
- 签名: `int IPSEC_PKT_ParseAndVerifyHdr(...)`
- 污点输入: `mbuf` — 外部网络数据包缓冲区

---

## 污点源

| 参数 | 类型 | 状态 | 说明 |
|------|------|------|------|
| `mbuf` | (mbuf*) | 🔴 TAINTED | 外部网络数据包缓冲区，由调用者传入 |

---

## 新导入的污点对象

| 对象 | 类型 | 状态 | 导入方式 | 位置 |
|------|------|------|----------|------|
| `ip_header` | uint8_t* | 🔴 TAINTED | `MBUF_MakeMemoryContinuous_fl(mbuf, 0, 40, ...)` 输出指针 | L10415 |
| `ext_header` | uint8_t* | 🔴 TAINTED | `MBUF_MakeMemoryContinuous_fl(mbuf, offset, len, ...)` 输出指针 | L10490/L10567/L10695/L10712 |
| `ah_header` | uint8_t* | 🔴 TAINTED | `MBUF_MakeMemoryContinuous_fl(mbuf, offset, len, ...)` 输出指针 | L10520 |
| `esp_header` | uint8_t* | 🔴 TAINTED | `MBUF_MakeMemoryContinuous_fl(mbuf, offset, len, ...)` 输出指针 | L10540 |
| `offset` | uint16_t | 🔴 TAINTED | 由污点 `ext_header[1]` 驱动增长 | L10572/L10705/L10720 |
| `next_header` | uint8_t | 🔴 TAINTED | 由 `ext_header[0]` 提取 | 多处 |
| `total_packet_len` | uint16_t | 🔴 TAINTED | 由污点 `packet_len_field` 计算 | L10445 |
| `state[PST_SPI]` | uint32_t | 🔴 TAINTED | 由污点 SPI 数据写入输出参数 | L10527/L10546 |
| `state[PST_HDR_OFFSET]` | uint16_t | 🔴 TAINTED | 由污点偏移写入输出参数 | L10526 |
| `state[PST_PACKET_LEN]` | uint16_t | 🔴 TAINTED | 由污点长度字段写入输出参数 | L10442 |
| `state[PST_TOTAL_LEN]` | uint32_t | 🔴 TAINTED | 由污点 total_data_len 写入输出参数 | L10444 |

---

## 传播路径图

```
mbuf 🔴 TAINTED (外部网络输入)
└── L10415: MBUF_MakeMemoryContinuous_fl(mbuf, 0, 40, ...)
    └── ip_header 🔴 TAINTED (新污点载体)
        ├── L10435: RAW_U8(ip_header, 0) → version_nibble 🔴 TAINTED
        ├── L10442: RAW_U16(ip_header, 4) → state[PST_PACKET_LEN] 🔴 TAINTED
        │   └── state[PST_PACKET_LEN] → 📌 USED (写入state数组)
        ├── L10444: state[PST_TOTAL_LEN] = (uint32_t)total_data_len 🔴 TAINTED
        │   └── state[PST_TOTAL_LEN] → 📌 USED (写入state数组)
        ├── L10444–L10445: packet_len_field + 40 → total_packet_len 🔴 TAINTED
        │   └── total_packet_len → 📌 USED (长度计算)
        ├── L10460: RAW_U8(ip_header, 6) → next_header 🔴 TAINTED
        │   └── next_header → 📌 USED (扩展头类型判断)
        └── while(1) 循环 — IPv6 扩展头链解析
            ├── [路由44 Fragment]
            │   └── L10490: MBUF_MakeMemoryContinuous_fl(mbuf, offset, 8, ...)
            │       └── ext_header 🔴 TAINTED
            │           ├── ext_header[0] → next_header 🔴 TAINTED
            │           └── offset += 8 (固定步长)
            │
            ├── [路由51 AH]
            │   └── L10520: MBUF_MakeMemoryContinuous_fl(mbuf, offset, total_len-offset, ...)
            │       └── ah_header 🔴 TAINTED
            │           ├── L10526: state[PST_HDR_OFFSET] = offset → 📌 USED
            │           └── L10527: state[PST_SPI] = bswap32(ah_header[4]) → 📌 USED
            │
            ├── [路由50 ESP]
            │   └── L10540: MBUF_MakeMemoryContinuous_fl(mbuf, offset, total_len-offset, ...)
            │       └── esp_header 🔴 TAINTED
            │           └── L10546: state[PST_SPI] = bswap32(*esp_header) → 📌 USED
            │
            ├── [路由60 Destination-Option]
            │   └── L10567: MBUF_MakeMemoryContinuous_fl(mbuf, offset, 2, ...)
            │       └── ext_header 🔴 TAINTED
            │           ├── ext_header[0] → next_header 🔴 TAINTED
            │           └── L10572: ⚠️ DIRECT_SINK: offset += 8*(ext_header[1]+1)
            │               └── 步长由污点 ext_header[1] 控制
            │
            ├── [路由0 Hop-by-Hop]
            │   └── L10695: MBUF_MakeMemoryContinuous_fl(mbuf, offset, 2, ...)
            │       └── ext_header 🔴 TAINTED
            │           ├── ext_header[0] → next_header 🔴 TAINTED
            │           └── L10705: ⚠️ DIRECT_SINK: offset += 8*(ext_header[1]+1)
            │               └── 步长由污点控制
            │
            └── [路由43 Routing]
                └── L10712: MBUF_MakeMemoryContinuous_fl(mbuf, offset, 4, ...)
                    └── ext_header 🔴 TAINTED
                        ├── ext_header[0] → next_header 🔴 TAINTED
                        └── L10720: ⚠️ DIRECT_SINK: offset += 8*(ext_header[1]+1)
                            └── 步长由污点控制
```

---

## 高危 Sink 汇总

| 污点字段 | 位置 | 风险描述 |
|----------|------|----------|
| `ext_header[1]` | L10572 | ⚠️ DIRECT_SINK: IPv6 扩展头长度字段，可导致指针越界 |
| `ext_header[1]` | L10705 | ⚠️ DIRECT_SINK: IPv6 扩展头长度字段，可导致指针越界 |
| `ext_header[1]` | L10720 | ⚠️ DIRECT_SINK: IPv6 扩展头长度字段，可导致指针越界 |
| `offset` | 循环条件 | ⚠️ DIRECT_SINK: 偏移量由污点数据驱动，可能导致缓冲区越界读取 |
| `total_len - offset` | L10520/L10540 | ⚠️ DIRECT_SINK: 读取大小由污点偏移控制，可导致越界读取 |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `state[PST_PACKET_LEN]` | 写入 state 数组 | L10442 | IP 包长度存储 |
| `state[PST_TOTAL_LEN]` | 写入 state 数组 | L10444 | 总长度存储 |
| `state[PST_HDR_OFFSET]` | 写入 state 数组 | L10526 | AH 头偏移存储 |
| `state[PST_SPI]` | 写入 state 数组 | L10527/L10546 | SPI 值存储 |
| `offset` | MBUF_MakeMemoryContinuous_fl 参数 | L10490等 | 控制后续读取位置 |

---

## [23/61] IPSEC_PKT_ParseAndVerifyHdrV4  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_PKT_ParseAndVerifyHdrV4

## 函数信息
- **文件**: libipsec.c
- **签名**: `int IPSEC_PKT_ParseAndVerifyHdrV4(..., int64_t mbuf, packet_state packet_state, ...)`

## 污点源

| ID | 参数 | 类型 | 状态 | 说明 |
|----|------|------|------|------|
| INPUT-1 | mbuf | int64_t | 🔴 TAINTED | 外部网络数据包缓冲区 |
| INPUT-2 | packet_state | packet_state | 🔴 TAINTED | 外部网络输入的状态结构体指针 |

---

## 新导入的污点对象

| ID | 对象 | 类型 | 导入方式 | 行号 |
|----|------|------|----------|------|
| NEW-1 | ip_header | uint8_t* | MBUF_MakeMemoryContinuous_fl 提取 | L11191 |
| NEW-2 | total_data_len | int | MBUF_GetTotalDataLength 读取 | L11226 |
| NEW-3 | esp_header | uint32_t* | MBUF_MakeMemoryContinuous_fl 提取 | L11259 |
| NEW-4 | ah_header | int64_t | MBUF_MakeMemoryContinuous_fl 提取 | L11329 |
| NEW-5 | state | uint8_t* | (uint8_t*)packet_state 类型转换 | L11168 |

---

## 数据流树状图

### INPUT-1: mbuf (int64_t) 🔴 TAINTED
```
[L11191] MBUF_MakeMemoryContinuous_fl(mbuf, 0, 20, ...)
  └── ip_header 🔴 TAINTED (NEW-1)
      ├── [L11204] version_nibble = ip_header[0] → version_nibble 🔴 TAINTED
      │   └── [L11218] header_len = 4 * (version_nibble & 0xF) → header_len 🔴 TAINTED
      │       ├── [L11259] esp_header = MBUF_MakeMemoryContinuous_fl(mbuf, header_len, ...)
      │       │   ├── esp_header 🔴 TAINTED (NEW-3) ⚠️ DIRECT_SINK: offset/size 由污点控制
      │       │   └── [L11278] SPI = bswap32(*esp_header)
      │       └── [L11329] ah_header = MBUF_MakeMemoryContinuous_fl(mbuf, header_len, ...)
      │           ├── ah_header 🔴 TAINTED (NEW-4) ⚠️ DIRECT_SINK: offset/size 由污点控制
      │           └── [L11347] SPI = bswap32(RAW_U32(ah_header, 4))
      ├── [L11243] IPSEC_LIB_Ipv4AddrToStr(ip_header[12], src_addr_text, 16) 📎
      └── [L11243] IPSEC_LIB_Ipv4AddrToStr(ip_header[16], dst_addr_text, 16) 📎

[L11226] total_data_len = MBUF_GetTotalDataLength(mbuf) → total_data_len 🔴 TAINTED (NEW-2)
  └── [L11228] RAW_U32(state, PST_TOTAL_LEN) = total_data_len

[L11239] next_proto = ip_header[9] → next_proto 🔴 TAINTED
  └── [L11376] RAW_U8(state, PST_NEXT_PROTO) = (uint8_t)next_proto

[L11248] dst_ipv4 = bswap32(ip_header[16]) → dst_ipv4 🔴 TAINTED
  └── [L11253] RAW_U32(state, PST_DST4_RAW) = dst_ipv4
```

### INPUT-2: packet_state (packet_state) 🔴 TAINTED
```
[L11168] state = (uint8_t*)packet_state → state 🔴 TAINTED (NEW-5)
  ├── [L11217] if (RAW_U8(state, PST_OUTPUT_FLAG) == 1) — 仅读取
  ├── [L11218] RAW_U16(state, PST_PACKET_LEN) = __builtin_bswap16(...) — 写入
  ├── [L11224] packet_len_field = RAW_U16(state, PST_PACKET_LEN) — 读取
  ├── [L11225] RAW_U32(state, PST_TOTAL_LEN) = total_data_len — 写入
  ├── [L11276] if (RAW_U8(state, PST_OUTPUT_FLAG) != 0) — 仅读取
  ├── [L11293] MBUF_MakeMemoryContinuous_fl(mbuf, header_len, RAW_U32(state, PST_TOTAL_LEN) - header_len, ...)
  │   └── ⚠️ DIRECT_SINK: 长度参数由污点数据决定
  ├── [L11306] RAW_U8(state, PST_PROTO) = 50 — 写入
  ├── [L11307] RAW_U32(state, PST_HDR_OFFSET) = header_len — 写入
  ├── [L11308] RAW_U32(state, PST_SPI) = __builtin_bswap32(*esp_header) — 写入
  ├── [L11309] IPSEC_PKT_DebugPacketV4(..., RAW_U32(state, PST_PKT_KIND)) 📎
  ├── [L11310] IPSEC_LIBI_GetManualSa(lib_ctx, packet_state, 0) 📎
  ├── [L11297] IPSEC_MakeDbgLibStrSetter(..., RAW_U32(state, PST_SPI), ...) 📎
  ├── [L11354] if (RAW_U8(state, PST_OUTPUT_FLAG) != 0) — 仅读取
  ├── [L11361] IPSEC_MakeDbgLibStrSetter(..., RAW_U32(state, PST_SPI), ...) 📎
  ├── [L11391] RAW_U8(state, PST_PROTO) = 51 — 写入
  ├── [L11392] RAW_U32(state, PST_HDR_OFFSET) = header_len — 写入
  ├── [L11393] RAW_U32(state, PST_SPI) = ... — 写入
  ├── [L11413] RAW_U32(state, PST_SPI) — 读取
  ├── [L11428] RAW_U32(state, PST_SPI) — 读取
  ├── [L11454] if (RAW_U8(state, PST_OUTPUT_FLAG) == 0) — 仅读取
  ├── [L11459] IPSEC_PKT_DebugPacketV4(..., RAW_U32(state, PST_PKT_KIND)) 📎
  ├── [L11464] IPSEC_PKT_DebugPacketV4(..., RAW_U32(state, PST_PKT_KIND)) 📎
  ├── [L11476] RAW_U8(state, PST_NEXT_PROTO) = (uint8_t)next_proto — 写入
  └── [L11477] RAW_U32(state, PST_HDR_OFFSET) = header_len — 写入
```

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf | 📎 USED | L11191, L11259, L11329 | MBUF_MakeMemoryContinuous_fl 提取数据 |
| ip_header | 📎 USED | L11243 | IPSEC_LIB_Ipv4AddrToStr 地址转字符串 |
| esp_header | ⚠️ DIRECT_SINK | L11259 | offset/size 由污点 header_len 控制 |
| ah_header | ⚠️ DIRECT_SINK | L11329 | offset/size 由污点 header_len 控制 |
| state | ⚠️ DIRECT_SINK | L11293 | MBUF_MakeMemoryContinuous_fl 长度参数来自污点 |

---

## 高危 DIRECT_SINK

| 模式 | 位置 | 说明 |
|------|------|------|
| MBUF_MakeMemoryContinuous_fl offset/size 可控 | L11259, L11329 | esp_header/ah_header 提取由 header_len 控制 |
| MBUF_MakeMemoryContinuous_fl 长度参数可控 | L11293 | PST_TOTAL_LEN 由 total_data_len 写入 |

---

## 子函数跟入表

| 函数 | 行号 | 污点参数 | 来源 |
|------|------|----------|------|
| MBUF_MakeMemoryContinuous_fl | L11191 | mbuf | INPUT-1 |
| MBUF_GetTotalDataLength | L11226 | mbuf | INPUT-1 |
| MBUF_MakeMemoryContinuous_fl | L11259 | mbuf | INPUT-1 |
| MBUF_MakeMemoryContinuous_fl | L11329 | mbuf | INPUT-1 |
| IPSEC_LIB_Ipv4AddrToStr | L11243 | ip_header | NEW-1 |
| IPSEC_LIBI_GetManualSa | L11280, L11310 | packet_state | INPUT-2 |
| IPSEC_PKT_DebugPacketV4 | L11309,L11315,L11373,L11380,L11459,L11464 | PST_PKT_KIND | NEW-5 |
| IPSEC_MakeDbgLibStrSetter | L11297,L11300,L11361,L11364 | PST_SPI | NEW-5 |

---

## [24/61] IPSEC_PKT_DebugPacketV4  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `send_if_index` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_PKT_DebugPacketV4

## 函数信息
- 文件: libipsec.c
- 函数范围: L11130-L11159
- 签名: `int64_t IPSEC_PKT_DebugPacketV4(int64_t lib_ctx, int64_t sa_stats, int dst_ipv4, unsigned int debug_mode, int packet_kind)`

## 数据流树状图

### INPUT-1: packet_kind (int) 🔴 TAINTED
├── [L11130-L11159] 函数体分析
│   ├── [L11133-L11134] 局部变量声明：sa_filter, packet_filter（未使用packet_kind）
│   ├── [L11136] debug_mode = (uint8_t)debug_mode → 仅处理debug_mode，packet_kind未被参与
│   └── [L11137-L11159] 条件分支与返回值
│       ├── 条件判断仅涉及：debug_mode, lib_ctx, sa_stats, dst_ipv4, packet_filter
│       └── 返回值：debug_mode(0) 或 布尔表达式 → 🟢 CLEANED
│
└── 结论：packet_kind在函数体内从未被引用，污点终止于入口

## 污点传播汇总

| 污点变量 | 状态 | 终点位置 | 说明 |
|---------|------|---------|------|
| packet_kind | 🔴 TAINTED | L11130-L11159 | 参数未使用，污点终止于函数入口 |

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| packet_kind | ❌ 未使用 | L11130-L11159 | 参数在函数内完全未引用，污点终止 |

## 特殊标记
- ⚠️ 无 DIRECT_SINK 危险操作
- ⚠️ 无缓冲区操作
- ⚠️ 无污点传播至子函数
- ⚠️ send_if_index 不在此函数签名中（任务中提及但函数无此参数）

## 分析备注
- 函数签名**不包含** `send_if_index` 参数
- `packet_kind` 作为污点参数传入后**完全未使用**
- 函数仅使用 `debug_mode`、`lib_ctx`、`sa_stats`、`dst_ipv4` 等未污染参数
- 返回值为条件判断结果，与污点参数无关
- 当前函数无污点传播风险

---

## [25/61] IPSEC_MakeDbgLibStrSetter  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `esp_spi` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_MakeDbgLibStrSetter

## 函数信息
- 文件: libipsec.c
- 行号: L21496 (函数入口)
- 签名: `int64_t IPSEC_MakeDbgLibStrSetter(int64_t lib_ctx, int comp_id, int line_no, const char *fmt, ...)`

## 数据流树状图

### INPUT-1: esp_spi (uint32_t) 🔴 TAINTED
├── [L21496] 函数入口 — esp_spi 作为 variadic 参数接收
│   来源: control_info[1] ← MBUF_GetControlInfo() — 外部网络输入
│   调用点: L11661 调用 IPSEC_MakeDbgLibStrSetter(..., esp_spi, ah_spi)
│
├── [L21512] va_start(ap, fmt)
│   └── esp_spi 🔴 TAINTED — 进入 variadic 参数列表
│
└── [L21513] vsnprintf_truncated_s(out_str + prefix_len, 513 - prefix_len, fmt, ap)
    │   esp_spi 作为 variadic 实参传入 ap
    │   格式字符串为 "ESP-SPI is %d, AH-SPI is %d" (字面量，安全)
    │   esp_spi 按 %d 格式化 → 十进制整数 (安全转换)
    │
    └── [L21514] va_end(ap)
        └── 📌 USED — 格式化结果写入 out_str (lib_ctx + 448)
            └── 后续调用 SSP_Debug(..., "%s", lib_ctx + 448) 用于调试输出

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| esp_spi | 📌 USED | L21513 | 作为 variadic 参数传递给 vsnprintf_truncated_s，最终格式化到调试字符串 |

## 新引入的污点对象
无 — 函数内无输出参数写入操作，所有操作均为对本函数参数的直接处理。

## 安全说明
- 格式字符串 `fmt` 为硬编码字面量 `"ESP-SPI is %d, AH-SPI is %d"`，攻击者无法控制
- `esp_spi` 按 `%d` 格式化，无指针解释风险

---

## [26/61] IPSEC_AH_HandleOutputPktV4  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_AH_HandleOutputPktV4

## 函数信息
- 文件: libipsec.c
- 函数签名: `int IPSEC_AH_HandleOutputPktV4(void* mbuf_base, unsigned int* parse_state)`

## 外部输入参数(已污染)
| 参数 | 类型 | 来源 |
|------|------|------|
| `mbuf_base` | `void*` | 外部网络数据包缓冲区 |
| `parse_state` | `unsigned int*` | 调用者通过 `IPSEC_PKT_ParseAndVerifyHdrV4()` 从 IPv4 网络包解析得到的 64 字节缓冲区 (packet_info) |

---

## 数据流树状图

### INPUT-1: mbuf_base (void*) 🔴 TAINTED
```
├── [L6188] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf_base, 0, packet_info[0], ...)
│   └── ip_header 🔴 TAINTED
│       ├── [L6195] IPSEC_LIB_Ipv4AddrToStr(ip_header+12, ...) → src_addr_text 🟢 CLEANED (仅格式化)
│       ├── [L6196] IPSEC_LIB_Ipv4AddrToStr(ip_header+16, ...) → dst_addr_text 🟢 CLEANED (仅格式化)
│       ├── [L6208] RAW_U8(ip_header, 9) = 51 → mbuf 被修改
│       └── [L6209] RAW_U16(ip_header, 2) = ... → mbuf 被修改
│
├── [L6229] LOOP: chunk_base = MBUF_MakeMemoryContinuous_fl(mbuf_base, read_offset, chunk_len, ...)
│   └── chunk_base 🔴 TAINTED
│       └── [L6235] memcpy_s(payload_cursor, chunk_len, chunk_base, chunk_len)
│           ⚠️ DIRECT_SINK: chunk_base(污点指针) + chunk_len(污点大小) 控制拷贝
│           └── payload_copy 🔴 TAINTED (新污点对象)
│               ├── [L6518] algo_desc[7](auth_ctx, payload_copy, payload_offset)
│               └── [L6527] algo_desc[7](auth_ctx, payload_copy, payload_offset)
│
├── [L6467] MBUF_CopyDataFromMBufToBuffer(mbuf_base, 0, packet_info[0], header_copy)
│   └── header_copy 🔴 TAINTED (新污点对象)
│       ├── [L6476] saved_tos = header_copy[1]
│       ├── [L6477] saved_id = *(uint16_t*)(header_copy+4)
│       ├── [L6478] saved_frag_off = *(uint16_t*)(header_copy+6)
│       ├── [L6479] saved_ttl = header_copy[8]
│       ├── [L6498] chunk_len = header_copy[option_offset + 1]
│       │   ⚠️ DIRECT_SINK: 选项长度字段来自污点数据，控制解析进度
│       ├── [L6502] algo_desc[7](auth_ctx, header_copy + option_offset, chunk_len)
│       ├── [L6508] header_len = 4u * (header_copy[0] & 0xF)
│       │   ⚠️ DIRECT_SINK: 头部长度字段来自污点数据，控制循环边界
│       ├── [L6519] ip_header = MBUF_MakeMemoryContinuous_fl(...) → ip_header 🔴 TAINTED 刷新
│       ├── [L6529] MBUF_CopyDataFromBufferToMBuf(mbuf_base, 0, packet_info[0], header_copy, ...)
│       │   ⚠️ DIRECT_SINK: 污点 header_copy 写回 mbuf
│       └── [L6534] memcpy_s(auth_header+12, auth_hash_len, auth_value, auth_hash_len)
│
├── [L6513] MBUF_PrependMemorySpace_fl(mbuf_base, auth_hash_len + 12, ...)
│   └── mbuf 被重新分配
│
└── [L6547] MBUF_CopyDataFromBufferToMBuf(mbuf_base, packet_info[0], auth_hash_len+12, auth_header, ...)
    ⚠️ DIRECT_SINK: auth_header(含mbuf来源数据) 写入 mbuf 偏移 packet_info[0]
```

### INPUT-2: parse_state (unsigned int*) 🔴 TAINTED
```
├── [L6181] debug_flow = bswap32(packet_info[13])
│   └── debug_flow 🔴 TAINTED
│
├── [L6191] MBUF_MakeMemoryContinuous_fl(..., packet_info[0], ...)
│   └── 📎 MBUF_MakeMemoryContinuous_fl (offset 参数)
│
├── [L6210] sa_lookup_key = packet_info[3]
│   └── sa_lookup_key 🔴 TAINTED
│       └── [L6212] VOS_AVL3_Find(..., &sa_lookup_key, ...)
│           └── ⚠️ DIRECT_SINK: SPI 直接控制 SA 查找键
│
├── [L6281] payload_len = packet_info[4]
│   └── payload_len 🔴 TAINTED
│       └── [L6282] payload_offset = payload_len - packet_info[0]
│           └── payload_offset 🔴 TAINTED
│               ├── [L6300] VRP_Malloc_F(..., payload_offset, ...)
│               │   └── ⚠️ DIRECT_SINK: 分配大小由污点控制
│               ├── [L6319] read_offset = packet_info[0]
│               │   └── read_offset 🔴 TAINTED
│               │       └── [L6326] LOOP: MBUF_MakeMemoryContinuous_fl(..., read_offset, chunk_len, ...)
│               │           ├── [L6235] memcpy_s(..., chunk_base, chunk_len) ⚠️ DIRECT_SINK
│               │           └── [L6502] algo_desc[7](auth_ctx, header_copy + option_offset, chunk_len)
│               └── [L6507] 写入 IP 头总长字段
│
├── [L6283] packet_info[5] = payload_offset
│   └── packet_info[5] 🔴 TAINTED (输出参数回写)
│
├── [L6284] packet_info[6] = payload_offset + 12
│   └── packet_info[6] 🔴 TAINTED (输出参数回写)
│
├── [L6298] IP 总长字段 = *(uint16_t*)(packet_info+5) + ...
│   └── ⚠️ DIRECT_SINK: 总长由污点计算
│
├── [L6390] auth_header[0] = *(packet_info+32)
│   └── auth_header[0] 🔴 TAINTED (Next Header 来自污点)
│       └── ⚠️ DIRECT_SINK: Next Header 由污点控制
│
├── [L6393] auth_header[4..7] = bswap32(packet_info[3])
│   └── auth_header[4..7] 🔴 TAINTED (SPI 写入 AH 头)
│       └── ⚠️ DIRECT_SINK: SPI 由污点写入，影响后续 SA 查找
│
├── [L6402] VRP_Malloc_F(..., packet_info[0], ...)
│   └── ⚠️ DIRECT_SINK: 分配大小由污点控制
│
├── [L6432] MBUF_CopyDataFromMBufToBuffer(..., packet_info[0], ...)
│   └── ⚠️ DIRECT_SINK: 拷贝大小由污点控制
│
├── [L6460] if (packet_info[0] < header_len)
│   └── 边界检查由污点数据参与
│
└── [L6547, L6559] MBUF_CopyDataFromBufferToMBuf(..., packet_info[0], ...)
    └── ⚠️ DIRECT_SINK: 偏移由污点控制
```

---

## 新引入的污点对象 (Within Current Function)

| 对象名 | 行号 | 来源函数/操作 | 类型 |
|--------|------|---------------|------|
| `ip_header` | L6188 | MBUF_MakeMemoryContinuous_fl | 返回值 |
| `chunk_base` | L6229 | MBUF_MakeMemoryContinuous_fl (循环) | 返回值 |
| `header_copy` | L6467 | MBUF_CopyDataFromMBufToBuffer | 输出参数 |
| `payload_copy` | L6235 | memcpy_s | 拷贝结果 |
| `auth_header` | L6390 | 分配+写入 parse_state 数据 | 局部缓冲区 |
| `sa_lookup_key` | L6210 | packet_info[3] 赋值 | 派生值 |
| `payload_len` | L6281 | packet_info[4] 赋值 | 派生值 |
| `payload_offset` | L6282 | payload_len - packet_info[0] | 计算值 |
| `read_offset` | L6319 | packet_info[0] 赋值 | 派生值 |
| `debug_flow` | L6181 | bswap32(packet_info[13]) | 派生值 |

---

## 污点终点汇总

| 脏数据 | 终点类型 | 位置 | 说明 |
|--------|---------|------|------|
| `mbuf_base` | ⚠️ DIRECT_SINK | L6235 | memcpy: 污点指针+污点大小控制拷贝 |
| `mbuf_base` | ⚠️ DIRECT_SINK | L6498 | header_copy[option_offset+1] 控制解析进度 |
| `mbuf_base` | ⚠️ DIRECT_SINK | L6508 | header_copy[0]&0xF 控制循环边界 |
| `mbuf_base` | ⚠️ DIRECT_SINK | L6513 | MBUF_PrependMemorySpace 重新分配 |
| `mbuf_base` | ⚠️ DIRECT_SINK | L6529 | 污点数据写回 mbuf |
| `mbuf_base` | ⚠️ DIRECT_SINK | L6547 | auth_header(含mbuf数据) 写入mbuf |
| `chunk_base` | ⚠️ DIRECT_SINK | L6235 | memcpy_s: chunk_len 大小来自污点 |
| `header_copy` | ⚠️ DIRECT_SINK | L6529 | 污点数据写回 mbuf |
| `parse_state[0]` | ⚠️ DIRECT_SINK | L6191, L6326 | 偏移/大小参数传入内存操作 |
| `parse_state[3]` | ⚠️ DIRECT_SINK | L6212 | SPI 直接控制 SA 查找键 |
| `parse_state[4]` | ⚠️ DIRECT_SINK | L6300 | payload_offset 控制分配大小 |
| `parse_state[3]` | ⚠️ DIRECT_SINK | L6393 | SPI 写入 AH 头，影响后续 SA 查找 |
| `parse_state[32]` | ⚠️ DIRECT_SINK | L6390 | Next Header 由污点控制 |
| `parse_state[0]` | ⚠️ DIRECT_SINK | L6402 | packet_info[0] 控制分配大小 |
| `parse_state[0]` | ⚠️ DIRECT_SINK | L6432 | packet_info[0] 控制拷贝大小 |
| `parse_state[0]` | ⚠️ DIRECT_SINK | L6547, L6559 | packet_info[0] 控制写回偏移 |
| `payload_len/payload_offset` | ⚠️ DIRECT_SINK | L6507 | 总长字段由污点计算并写入 |
| `packet_info[5]` | ⚠️ DIRECT_SINK | L6298 | 总长由污点计算 |

---

## 外部库函数标记

| 函数 | 行号 | 说明 |
|------|------|------|
| `MBUF_MakeMemoryContinuous_fl` | L6188, L6191, L6229, L6326, L6519, L6522 | 外部内存连续化库函数 🟡 EXPORT |
| `MBUF_CopyDataFromMBufToBuffer` | L6467, L6432 | 外部内存拷贝库函数 🟡 EXPORT |
| `MBUF_CopyDataFromBufferToMBuf` | L6529, L6547, L6559 | 外部内存拷贝库函数 🟡 EXPORT |
| `MBUF_PrependMemorySpace_fl` | L6513 | 外部内存重分配库函数 🟡 EXPORT |
| `memcpy_s` | L6235, L6534 | 标准库函数 🟡 EXPORT |

---

## [27/61] __builtin_bswap32  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: __builtin_bswap32

## 函数信息
- 文件: libipsec.c
- 行号: (compiler builtin)
- 签名: `uint32_t __builtin_bswap32(uint32_t x)`

## 数据流树状图

### INPUT-1: x (uint32_t) 🔴 TAINTED
├── [L11628] `dst_ipv4 = __builtin_bswap32(RAW_U32(parse_state, 52))`
│   └── dst_ipv4 🔴 TAINTED
│       ├── [L11640] `IPSEC_PKT_DebugPacketV4(lib_ctx, manual_sa, dst_ipv4, ...)` → 📎 见 tainted.list
│       └── [L11753] `IPSEC_PKT_DebugPacketV4(lib_ctx, manual_sa, dst_ipv4, ...)` → 📎 见 tainted.list
└── [L11830] `dst_ipv4 = __builtin_bswap32(RAW_U32(parse_state, 52))`
    └── dst_ipv4 🔴 TAINTED
        └── [L11843] `IPSEC_PKT_DebugPacketV4(lib_ctx, manual_sa, dst_ipv4, ...)` → 📎 见 tainted.list

## 污点溯源
- `x` 接收自 `RAW_U32(parse_state, 52)` → 读取自外部网络包解析后的 `parse_state[52:56]` (PST_DST4_RAW)
- `parse_state` 初始来源: `IPSEC_PKT_ParseAndVerifyHdrV4` 写入 (L11253)

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| x → dst_ipv4 | 📎 子函数 | L11640 | 传入 IPSEC_PKT_DebugPacketV4 |
| x → dst_ipv4 | 📎 子函数 | L11753 | 传入 IPSEC_PKT_DebugPacketV4 |
| x → dst_ipv4 | 📎 子函数 | L11843 | 传入 IPSEC_PKT_DebugPacketV4 |

---

## [28/61] RAW_U8  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: RAW_U8

## 函数信息
- 文件: libipsec.c
- 函数类型: 宏/内联函数 (内存写入操作)
- 污点接收参数: packet_info[1] - 作为指针偏移量传入

## 数据流树状图

### INPUT-1: packet_info[1] (parse_state[4..7]) 🔴 TAINTED
├── parse_state ← 🔴 TAINTED (网络数据，由 IPSEC_PKT_ParseAndVerifyHdr 填充)
│   └── parse_state[4..7] = PST_LAST_EXT_OFFSET ← 🔴 TAINTED (偏移量字段)
│       └── packet_info[1] = parse_state[4..7] ← 🔴 TAINTED
│           ├── [L5323] RAW_U8(ip_header, packet_info[1]) = 51
│           │   └── ⚠️ DIRECT_SINK: 污点偏移量控制指针，越界写入风险
│           ├── [L6074] RAW_U8(ip_header, packet_info[1]) = ah_header[0]
│           │   └── ⚠️ DIRECT_SINK: 污点偏移量控制指针，越界写入风险
│           ├── [L8485] RAW_U8(ip_header, packet_info[1]) = 50
│           │   └── ⚠️ DIRECT_SINK: 污点偏移量控制指针，越界写入风险
│           ├── [L9695] RAW_U8(ip_header, packet_info[1]) = esp_tail_block[enc_block_size-1]
│           │   └── ⚠️ DIRECT_SINK: 污点偏移量控制指针，越界写入风险
│           └── [L9697] RAW_U8(ip_header, packet_info[1]) = next_header
│               └── ⚠️ DIRECT_SINK: 污点偏移量控制指针，越界写入风险
│
└── 传播路径来源:
    ├── [L10446] offset += 8 * (ext_header[1] + 1) → offset 🔴 TAINTED (ext_header[1]来自网络)
    ├── [L10494] RAW_U32(state, PST_LAST_EXT_OFFSET) = offset → state[4..7] 🔴 TAINTED
    ├── [L10646] RAW_U32(state, PST_LAST_EXT_OFFSET) = offset → 污点传播
    ├── [L10690] RAW_U32(state, PST_LAST_EXT_OFFSET) = offset → 污点传播
    └── [L10713] RAW_U32(state, PST_LAST_EXT_OFFSET) = offset → 污点传播

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| packet_info[1] | RAW_U8(ip_header, packet_info[1]) | L5323 | ⚠️ DIRECT_SINK: AH输出处理，污点偏移写入 |
| packet_info[1] | RAW_U8(ip_header, packet_info[1]) | L6074 | ⚠️ DIRECT_SINK: AH输入处理，污点偏移写入 |
| packet_info[1] | RAW_U8(ip_header, packet_info[1]) | L8485 | ⚠️ DIRECT_SINK: ESP输出处理，污点偏移写入 |
| packet_info[1] | RAW_U8(ip_header, packet_info[1]) | L9695 | ⚠️ DIRECT_SINK: ESP输入处理，污点偏移写入 |
| packet_info[1] | RAW_U8(ip_header, packet_info[1]) | L9697 | ⚠️ DIRECT_SINK: ESP输入处理，污点偏移写入 |

## 子函数跟入列表 (接收污点数据)

| 调用函数 | 位置 | 接收的污点参数 |
|----------|------|----------------|
| IPSEC_PKT_ParseAndVerifyHdr | L10386 | mbuf, lib_ctx, packet_state |
| IPSEC_LIBI_GetManualSa | L10855 | lib_ctx, parse_state |
| IPSEC_AH_HandleInputPkt | L11062 | lib_ctx, mbuf, packet_info |
| IPSEC_AH_HandleOutputPkt | L10868 | lib_ctx, mbuf, packet_info |
| IPSEC_ESP_HandleInputPkt | L11085 | lib_ctx, mbuf, packet_info |
| IPSEC_ESP_HandleOutputPkt | L10897 | lib_ctx, mbuf, packet_info |

---

## [29/61] IPSEC_ESP_HandleOutputPktV4  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_ESP_HandleOutputPktV4

## 函数信息
- 文件: libipsec.c
- 签名: `void IPSEC_ESP_HandleOutputPktV4(void *lib_ctx, void *mbuf, unsigned int *parse_state)`
- 功能: ESP输出数据包处理（IPv4），封装IP包为ESP格式

## 污点源

| 编号 | 变量 | 类型 | 说明 |
|------|------|------|------|
| INPUT-1 | mbuf | mbuf指针 | 外部网络数据包mbuf结构，作为函数参数传入 🔴 TAINTED |
| INPUT-2 | parse_state | uint8_t[64] | 通过packet_info指针传入，来自外部控制信息 🔴 TAINTED |

### parse_state 关键字段映射
- `packet_info[0]` = PST_HDR_OFFSET ← IP头解析值，攻击者可控
- `packet_info[3]` = esp_spi ← `__builtin_bswap32(control_info[1])`，攻击者完全可控
- `packet_info[4]` = PST_TOTAL_LEN ← 从IP头解析
- `packet_info[5]` = payload_offset ← 由污点payload_offset派生后回写
- `packet_info[6]` = iv_len+8+payload_offset+tail_len
- `packet_info[13]` = DST4_RAW ← 目的IPv4地址
- `packet_info[29]` = tail_len
- `packet_info[31]` = block_size
- `packet_info[32]` = tail_len ← 由污点payload_offset派生后回写

---

## 数据流树状图

### INPUT-1: mbuf 🔴 TAINTED
```
mbuf 🔴 TAINTED
├── [L8792] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...)
│   └── ip_header 🔴 TAINTED → 指向mbuf中的IP头数据
│       └── [L8951] 修改IP头总长度字段 ⚠️ DIRECT_SINK
├── [L8872] packet_info[4], packet_info[5], pad_len, tail_len 等派生值
│   └── 均为 🔴 TAINTED → 依赖于mbuf中的原始包大小信息
├── [L8901] appended_tail = MBUF_AppendMemorySpace_fl(mbuf, auth_and_tail_len, ...)
│   └── appended_tail 🔴 TAINTED → 指向mbuf追加的尾部空间
│       ├── [L8906] 填充pad_len个padding字节（使用循环计数器，clean）
│       └── [L8908] appended_tail[pad_len + 1] = *((uint8_t *)packet_info + 32)
│           └── ⚠️ DIRECT_SINK: packet_info[32]被写入ESP尾部的下一头字段
├── [L8948] chunk = MBUF_MakeMemoryContinuous_fl(mbuf, dbg_type, chunk_len, ...)
│   └── chunk 🔴 TAINTED → 指向mbuf中的负载数据
│       └── [L8951] block_ptr = (uint8_t *)chunk
│           └── block_ptr 🔴 TAINTED
│               ├── [L8953] enc_desc[24](sa_entry, block_ptr, chunk_len) ⚠️ DIRECT_SINK
│               ├── [L8955] auth_desc[7](auth_ctx, block_ptr, block_size) ⚠️ DIRECT_SINK
│               └── [L8969] memcpy_s(sa_entry+80, block_ptr, iv_len) ⚠️ DIRECT_SINK
├── [L9076] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, *packet_info, scratch_buf)
│   └── scratch_buf 🔴 TAINTED → 包含mbuf数据副本的新污点载体
│       ├── [L9088] MBUF_CopyDataFromBufferToMBuf(mbuf, 0, *packet_info, scratch_buf, ...) ⚠️ DIRECT_SINK
│       └── [L9092] MBUF_CopyDataFromBufferToMBuf(mbuf, *packet_info, iv_len+8, esp_hdr, ...)
├── [L9080] MBUF_PrependMemorySpace_fl(mbuf, iv_len + 8, ...) ⚠️ DIRECT_SINK
└── [L9112] MBUF_PrependMemorySpace_fl(mbuf, iv_len + 8, ...) ⚠️ DIRECT_SINK
```

### INPUT-2: parse_state/packet_info 🔴 TAINTED
```
parse_state/packet_info 🔴 TAINTED
├── [L8791] dbg_flow = __builtin_bswap32(packet_info[13])
│   └── dbg_flow 🔴 TAINTED → 目的IPv4，影响调试分支条件
├── [L8792] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...)
│   └── ⚠️ DIRECT_SINK: *packet_info（=parse_state[0..3]）控制mbuf内存读取大小
├── [L8827] RAW_U32(&algo_dbg_word, 0) = packet_info[3]; RAW_U16(&algo_dbg_word, 4) = 50
│   └── algo_dbg_word 🔴 TAINTED → 攻击者SPI + 50（协议号）注入调试关键字
│       └── [L8835] VOS_AVL3_Find(lib_ctx+120, &algo_dbg_word, ...)
│           └── ⚠️ DIRECT_SINK: 污点SPI作为AVL树查找关键字
├── [L8908] dbg_type = packet_info[14]
│   └── dbg_type 🔴 TAINTED → send_if_index（mbuf元数据）
├── [L8927] packet_size = packet_info[4]
│   └── packet_size 🔴 TAINTED → PST_TOTAL_LEN（从IP头解析）
│       ├── [L8928] payload_offset = packet_size - *packet_info → payload_offset 🔴 TAINTED
│       │   └── [L8929] packet_info[5] = payload_offset → 写回parse_state[20..23]
│       ├── [L8930] pad_len = (block_size - ((payload_offset + 2) % block_size)) % block_size
│       │   └── pad_len 🔴 TAINTED
│       │       ├── [L8906] 循环填充 appended_tail[offset]（循环计数器clean）
│       │       └── [L8908] appended_tail[pad_len + 1] = *((uint8_t *)packet_info + 32)
│       ├── [L8931] tail_len = pad_len + 2 → tail_len 🔴 TAINTED
│       ├── [L8932] packet_info[6] = iv_len + 8 + payload_offset + tail_len → 写回parse_state[24..27]
│       ├── [L8935] *((uint8_t *)packet_info + 29) = (uint8_t)tail_len → 写回parse_state[29]
│       ├── [L8937] *((uint8_t *)packet_info + 31) = block_size → 写回parse_state[31]
│       ├── [L8938] *((uint8_t *)packet_info + 32) = (uint8_t)tail_len → 写回parse_state[32]
│       └── [L8936] new_packet_size = packet_size + iv_len + 8 + auth_and_tail_len → new_packet_size 🔴 TAINTED
│           └── ⚠️ DIRECT_SINK: packet_size（网络解析值）参与整数溢出检查 > 0xFFFF
│       └── [L8951] RAW_U16((void *)ip_header, 2) = *((uint16_t *)packet_info + 5) + 8 + ...
│           └── ⚠️ DIRECT_SINK: parse_state[10..11]（PST_PACKET_LEN）被写入IP头总长度字段
├── [L8970] offset = RAW_U32((void *)sa_entry, 76)
│   └── [L8972] esp_hdr[0] = __builtin_bswap32(packet_info[3])
│       └── esp_hdr[0] 🔴 TAINTED → 攻击者SPI被写入ESP头字段
│           └── [L9118] MBUF_CopyDataFromBufferToMBuf(mbuf, *packet_info, iv_len+8, &esp_hdr[0], ...)
│               └── ⚠️ DIRECT_SINK: 含攻击者SPI的ESP头被写入mbuf传出包
├── [L8974] esp_iv[0] = __builtin_bswap32(offset) → esp_iv[0]（可信，SA序列号）
├── [L8976] esp_hdr[1] = __builtin_bswap32(RAW_U32((void *)sa_entry, 76))
│   └── esp_hdr[1] 🔴 TAINTED
├── [L9013] dbg_type = *packet_info
│   └── dbg_type 🔴 TAINTED → 覆盖为 parse_state[0..3]（PST_HDR_OFFSET），攻击者可控
│       └── [L8948] chunk = MBUF_MakeMemoryContinuous_fl(mbuf, dbg_type, chunk_len, ...)
│           └── ⚠️ DIRECT_SINK: dbg_type（污点）控制内存连续化的类型参数
├── [L9042] chunk_len = packet_info[6] - iv_len - 8 - auth_hash_len - offset
│   └── chunk_len 🔴 TAINTED → packet_info[6] 来自 parse_state[24..27]
│       └── [L8948] chunk = MBUF_MakeMemoryContinuous_fl(mbuf, dbg_type, chunk_len, ...)
│           └── ⚠️ DIRECT_SINK: chunk_len（污点）控制mbuf内存读取大小
├── [L9107] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, *packet_info, scratch_buf)
│   └── ⚠️ DIRECT_SINK: *packet_info（parse_state[0..3]）控制复制大小
│       scratch_buf 🔴 TAINTED → 从mbuf读入完整IP包数据，成为新污点载体
│           ├── [L9115] MBUF_CopyDataFromBufferToMBuf(mbuf, *packet_info, ..., scratch_buf, ...)
│           │   └── ⚠️ DIRECT_SINK: 污点scratch_buf被写回mbuf
│           └── [L9122] MBUF_CopyDataFromBufferToMBuf(mbuf, ..., esp_hdr, ...)
├── [L9112] MBUF_PrependMemorySpace_fl(mbuf, iv_len + 8, ...)
│   └── ⚠️ DIRECT_SINK: mbuf被修改以准备接收ESP头
├── [L9095/L9121] 条件判断: dbg_flow/SPI值驱动debug分支 → 间接影响控制流
└── [L8914/L9095/L9121/L9124] IPSEC_PKT_DebugPacketV4(..., dbg_flow, ...) 📎 见跟入列表
```

---

## 新导入的污点对象（输出参数写入）

| 变量名 | 派生来源 | 派生位置 | 说明 |
|--------|---------|---------|------|
| ip_header | MBUF_MakeMemoryContinuous_fl返回值 | L8792 | 指向mbuf中的IP头数据 |
| appended_tail | MBUF_AppendMemorySpace_fl返回值 | L8901 | 指向mbuf追加的尾部空间 |
| chunk | MBUF_MakeMemoryContinuous_fl返回值 | L8948 | 指向mbuf中的负载数据 |
| block_ptr | chunk派生 | L8951 | 用于遍历处理负载块 |
| scratch_buf | MBUF_CopyDataFromMBufToBuffer写入 | L9076/L9107 | 包含mbuf数据副本的新污点载体 |
| esp_hdr[0] | packet_info[3]赋值 | L8972 | 承载攻击者控制的SPI值 |
| esp_hdr[1] | sa_entry偏移76赋值 | L8976 | 承载序列号 |
| algo_dbg_word | packet_info[3]赋值 | L8827 | 攻击者SPI + 50注入调试关键字 |
| dbg_flow | packet_info[13]赋值 | L8791 | 承载目的IPv4 |
| dbg_type | packet_info[0]覆盖 | L9013 | 被解析的头偏移覆盖 |
| payload_offset | packet_info[4]派生 | L8928 | 负载偏移量 |
| pad_len | payload_offset派生 | L8930 | 填充长度 |
| tail_len | pad_len派生 | L8931 | 尾部长度 |
| new_packet_size | packet_size派生 | L8936 | 新数据包大小 |
| chunk_len | packet_info[6]派生 | L9042 | 分块处理长度 |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| packet_info[3] (esp_spi) | 写入 esp_hdr[0] | L8972 | 攻击者SPI写入所有传出ESP包的SPI字段 |
| packet_info[3] | 写入 algo_dbg_word | L8827 | 污点SPI作为SA查找关键字 |
| packet_info[4] (TOTAL_LEN) | 控制内存操作大小 | L8792, L9107 | 来自IP头解析的长度值驱动内存读取/复制 |
| packet_info[6] (payload+tail+iv) | 控制循环边界 chunk_len | L9042 | 派生长度控制处理负载数据量 |
| packet_info[32] (tail_len) | 写入 ESP trailer | L8938, L8908 | 攻击者控制的tail_len值写入ESP尾部 |
| *packet_info (HDR_OFFSET) | 控制 dbg_type/mbuf操作 | L8792, L9013, L9115 | 解析的头偏移控制内存操作参数 |
| packet_info[13] (DST4) | 控制 debug flow | L8791 | 攻击者IP影响调试分支 |
| algo_dbg_word | 写入 SADB AVL树查找 | L8835 | 污点SPI作为安全关联数据库查找关键字 |
| esp_hdr[0] | 写入 mbuf 传出包 | L9118 | 攻击者SPI被写入传出ESP头 |
| scratch_buf | 完整IP包数据 | L9107 | 由parse_state长度控制复制生成新污点载体 |
| new_packet_size | 整数溢出检查 | L8936 | 网络解析长度参与数据包大小安全检查 |
| ip_header | 写入IP头总长度字段 | L8951 | 解析长度注入IP头 |
| appended_tail | 写入ESP尾部 | L8908 | 污点数据直接写入包尾部 |
| chunk/block_ptr | 加密/认证处理 | L8953, L8955, L8969 | 污点负载数据被送入加密和认证函数 |

---

## 关键DIRECT_SINK汇总

| 位置 | 操作 | 危险 |
|------|------|------|
| L8792 | `MBUF_MakeMemoryContinuous_fl(..., *packet_info, ...)` | `*packet_info`（parse_state[0..3]）控制内存读取大小 |
| L8827 | `algo_dbg_word = packet_info[3]` | 攻击者SPI注入调试关键字 |
| L8835 | `VOS_AVL3_Find(..., &algo_dbg_word, ...)` | 污点SPI作为AVL树查找关键字 |
| L8908 | `appended_tail[pad_len+1] = packet_info[32]` | 污点tail_len被写入ESP尾部下一协议字段 |
| L8930 | `pad_len = ... payload_offset ...` | payload_offset驱动pad_len，影响尾部填充循环边界 |
| L8938 | `*(packet_info + 32) = tail_len` | 污点tail_len写回parse_state[32] |
| L8951 | `ip_header[2] = *((uint16_t *)packet_info + 5) + ...` | parse_state[10..11]被注入IP头总长度字段 |
| L8953 | `enc_desc[24](sa_entry, block_ptr, chunk_len)` | 污点负载数据被送入加密函数 |
| L8955 | `auth_desc[7](auth_ctx, block_ptr, block_size)` | 污点数据影响HMAC认证计算 |
| L8969 | `memcpy_s(sa_entry+80, 16, block_ptr, iv_len)` | 最后密文块污染SA的IV状态 |
| L8972 | `esp_hdr[0] = packet_info[3]` | 攻击者SPI被写入ESP头SPI字段 |
| L9013 | `dbg_type = *packet_info` | parse_state[0..3]覆盖dbg_type，后续控制内存操作 |
| L9042 | `chunk_len = packet_info[6] - ...` | packet_info[6]控制循环边界 |
| L9076 | `MBUF_CopyDataFromMBufToBuffer(..., *packet_info, ...)` | 复制大小由parse_state控制 |
| L9088 | `MBUF_CopyDataFromBufferToMBuf(mbuf, scratch_buf)` | 污点scratch_buf被写回mbuf |
| L9107 | `MBUF_CopyDataFromMBufToBuffer(mbuf, scratch_buf)` | 新污点载体scratch_buf |
| L9115 | `MBUF_CopyDataFromBufferToMBuf(mbuf, *packet_info, ..., scratch_buf, ...)` | 偏移受控，scratch_buf含完整IP包 |
| L9118 | `MBUF_CopyDataFromBufferToMBuf(mbuf, ..., &esp_hdr[0], ...)` | 含攻击者SPI的ESP头被写入mbuf传出包 |
| L9080 | `MBUF_PrependMemorySpace_fl(mbuf, iv_len+8)` | mbuf被修改以接收ESP头 |
| L9112 | `MBUF_PrependMemorySpace_fl(mbuf, iv_len+8)` | mbuf被修改以准备接收ESP头 |

---

## [30/61] IPSEC_LIBI_GetManualSa  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIBI_GetManualSa

## 函数信息
- 文件: `libipsec.c`
- 签名: `int64_t IPSEC_LIBI_GetManualSa(int64_t lib_ctx, int64_t manual_sa_cfg, uint32_t *spi_or_ports)`
- 功能: 根据 `parse_state[64]` 缓冲区中的网络数据构造 SADB 查找键，查询 SA 数据库

## 污点源

### INPUT: `manual_sa_cfg` (int64_t → parse_state[64]) 🔴 TAINTED
- **来源**: 调用者处 `uint8_t parse_state[64]` 缓冲区，内容由 `IPSEC_PKT_ParseAndVerifyHdr` / `ParseAndVerifyHdrV4` 从网络 mbuf/IP 头的各字段填充后，以 `(int64_t)parse_state` 作为 `manual_sa_cfg` 传入
- **污点类型**: 外部网络输入

## 污点传播路径

```
### INPUT: manual_sa_cfg (int64_t → parse_state[64]) 🔴 TAINTED
│
├── [L10210] if (RAW_U8(manual_sa_cfg, 28) == 1)
│   ├── [L10211] if (spi_or_ports == NULL) → 🟢 CLEANED（空指针检查）
│   ├── [L10213] if (spi_or_ports[1] != 0)
│   │   ├── [L10214] RAW_U32(&lookup_key, 0) = spi_or_ports[1] → 🟢 CLEANED
│   │   └── [L10217] RAW_U32(&lookup_key, 0) = spi_or_ports[0] → 🟢 CLEANED
│   │   └── [L10215/L10218] RAW_U8(&lookup_key, 4) = 50/51 → 🟢 CLEANED
│   └── [L10220] RAW_U8(&lookup_key, 5) = 0 → 🟢 CLEANED
│       └── [L10227] VOS_AVL3_Find(..., &lookup_key, ...)
│           → 查找键源自 control_info（非 parse_state），🟢 CLEANED
│
└── [L10221] else:  RAW_U8(manual_sa_cfg, 28) != 1 → 🔴 TAINTED 分支
    │
    ├── [L10222] RAW_U32(&lookup_key, 0) = RAW_U32(manual_sa_cfg, 12)
    │   → lookup_key[0..3] 🔴 TAINTED
    │   → 读取 parse_state[12..15] (PST_SPI)，值来自网络 mbuf 中的 ESP/AH 头
    │   → ⚠️ DIRECT_SINK: 污点 SPI 值驱动 SA 查找键构造
    │
    ├── [L10223] RAW_U8(&lookup_key, 4) = RAW_U8(manual_sa_cfg, 8)
    │   → lookup_key[4] 🔴 TAINTED
    │   → 读取 parse_state[8] (PST_PREV_PROTO)，值来自网络 IP 头的协议字段
    │   → ⚠️ DIRECT_SINK: 污点协议字节参与 SA 查找键构造
    │
    ├── [L10224] RAW_U8(&lookup_key, 5) = 1 → 🟢 CLEANED（常量赋值）
    │
    ├── [L10227] VOS_AVL3_Find(lib_ctx + 120, &lookup_key, lib_ctx + 144)
    │   → ⚠️ DIRECT_SINK: lookup_key[0..4] 完全由网络数据构造（SPI + 协议），作为 SADB 查找键
    │
    └── [L10228] if (sa_entry != 0)
        └── [L10229] VOS_AVL3_Find(lib_ctx + 76, (const void *)(sa_entry + 132), lib_ctx + 100)
            → ⚠️ DIRECT_SINK: sa_entry 来自污点键控的第一次查找，其指针用于第二次查找
            └── [L10230] RETURN_GUARDED(sa_entry) → 📌 USED（SA 句柄返回调用者）
```

## 新导入的污点对象

| 对象名 | 类型 | 构造方式 | 污点来源 |
|--------|------|----------|----------|
| `lookup_key` | 结构体 | RAW_U32(&lookup_key, 0) = RAW_U32(manual_sa_cfg, 12); RAW_U8(&lookup_key, 4) = RAW_U8(manual_sa_cfg, 8) | manual_sa_cfg → parse_state[64] (网络数据) |

### lookup_key 传播下游
```
lookup_key 🔴 TAINTED (由 manual_sa_cfg 在 L10222-L10223 构造)
└── [L10227] VOS_AVL3_Find(..., &lookup_key, ...) → ⚠️ DIRECT_SINK
```

## 污点终点汇总

| 脏数据 | 终点类型 | 位置 | 说明 |
|--------|----------|------|------|
| manual_sa_cfg (parse_state[64]) | ⚠️ DIRECT_SINK | L10222 | 污点 SPI 值驱动 SA 查找键构造 |
| manual_sa_cfg (parse_state[64]) | ⚠️ DIRECT_SINK | L10223 | 污点协议字节参与 SA 查找键构造 |
| manual_sa_cfg (parse_state[64]) | ⚠️ DIRECT_SINK | L10227 | lookup_key 由网络数据构造，驱动 SADB 查找 |
| manual_sa_cfg (parse_state[64]) | ⚠️ DIRECT_SINK | L10229 | sa_entry 来自污点键控查找，作为二次查找参数 |
| manual_sa_cfg (parse_state[64]) | 📌 USED | L10230 | sa_entry 作为 SA 句柄返回给调用者 |

## 关键风险

1. **网络数据驱动 SADB 查找键**: `parse_state[12..15]` 中的 SPI 值和 `parse_state[8]` 中的协议值完全由网络数据控制
2. **SA 查找键构造**: 两个 DIRECT_SINK 标记点（L10222, L10223）确认污点数据参与 SADB 查找键构造
3. **双重查找依赖**: 第二次 VOS_AVL3_Find 的输入依赖于第一次查找结果，而第一次查找键完全由网络数据控制

---

## [31/61] IPSEC_AH_HandleOutputPkt  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_AH_HandleOutputPkt

## 函数信息
- 文件: libipsec.c
- 函数: IPSEC_AH_HandleOutputPkt
- 输入参数: mbuf, parse_state (unsigned int*)

---

## INPUT-1: mbuf (mbuf*) 🔴 TAINTED
> 外部输入网络数据包缓冲区

### 传播路径

```
[L5238] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf, 0, packet_info[0], ...)
    └── ip_header 🔴 TAINTED
        ├── [L5261] IPSEC_LIB_Ipv6AddrToStr(ip_header+8, src_addr_str, 65) → 提取源地址
        ├── [L5262] IPSEC_LIB_Ipv6AddrToStr(ip_header+24, dst_addr_str, 65) → 提取目的地址
        ├── [L5330] RAW_U8(ip_header, packet_info[1]) = 51 → 修改协议字段
        └── [L5332] RAW_U16(ip_header, 4) = ... → 修改 IP 长度

[L5348] chunk_base = MBUF_MakeMemoryContinuous_fl(mbuf, read_offset, copy_len, ...)
    └── chunk_base 🔴 TAINTED
        ├── [L5373] memcpy_s(payload_cursor, chunk_size, chunk_base, chunk_size)
        │   └── payload_copy 🔴 TAINTED（memcpy 目的端新载体）
        └── [L5407] 循环重复调用，返回 chunk_base

[L5405] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, packet_info[0], &header_copy)
    └── header_copy 🔴 TAINTED（输出参数导入）
        ├── [L5408] saved_word0 = RAW_U32(header_copy, 0) → 保存原始字段
        ├── [L5411] RAW_U32(header_copy, 0) = 0 → 清零操作
        ├── [L5447] RAW_U32(header_copy, 0) = saved_word0 → 恢复
        └── [L5471] MBUF_CopyDataFromBufferToMBuf(mbuf, ..., header_copy, ...)

[L5448] MBUF_PrependMemorySpace_fl(mbuf, ...) → mbuf 空间扩展
[L5455] MBUF_MakeMemoryContinuous_fl(mbuf, ...) → 重新获取 mbuf 指针
```

### 新导入的污点载体
| 对象 | 导入方式 | 行号 |
|------|----------|------|
| ip_header | MBUF_MakeMemoryContinuous_fl 返回数据指针 | L5238 |
| chunk_base | MBUF_MakeMemoryContinuous_fl 返回分块指针 | L5348, L5407 |
| header_copy | MBUF_CopyDataFromMBufToBuffer 输出参数 | L5405 |
| payload_copy | memcpy_s 目的端（chunk_base 污点传播） | L5373 |

---

## INPUT-2: parse_state (unsigned int*) 🔴 TAINTED
> 外部网络输入，作为 packet_info 数组使用

### 传播路径

```
packet_info[0] (IP头长度)
├── [L5248] → MBUF_MakeMemoryContinuous_fl 大小参数 → ip_header 🔴 TAINTED
│   ├── [L5323] RAW_U8((void *)ip_header, packet_info[1]) = 51 ⚠️ DIRECT_SINK: 污点索引写入
│   └── [L5328] RAW_U16((void *)ip_header, 4) = __builtin_bswap16(...)
├── [L5361] → MBUF_MakeMemoryContinuous_fl 偏移参数: read_offset
├── [L5381] → VRP_Malloc_F 分配大小 → header_copy 🔴 TAINTED
│   ├── [L5467] MBUF_CopyDataFromMBufToBuffer(..., packet_info[0], header_copy)
│   ├── [L5489] algo_desc[7](auth_ctx, header_copy, packet_info[0])
│   └── [L5526] MBUF_CopyDataFromBufferToMBuf(..., packet_info[0], header_copy, ...)
└── [L5549] → MBUF_CopyDataFromBufferToMBuf 偏移

packet_info[1] (下一头部类型)
├── [L5318-5319] → 条件分支判断
└── [L5323] RAW_U8((void *)ip_header, packet_info[1]) = 51 ⚠️ DIRECT_SINK: 污点索引写入

packet_info[3] (SA索引)
├── [L5267] → sa_lookup_key 🔴 TAINTED
│   └── [L5269] sa_entry = VOS_AVL3_Find(..., &sa_lookup_key, ...) → sa_entry 🔴 TAINTED
└── [L5427] → RAW_U32(auth_header, 4) → auth_header 🔴 TAINTED

packet_info[4] (负载长度)
├── [L5302-5303] → payload_len 🔴 TAINTED
│   └── payload_offset = payload_len - packet_info[0] → payload_offset 🔴 TAINTED
│       ├── [L5340] VRP_Malloc_F(..., payload_offset, ...) → payload_copy 🔴 TAINTED ⚠️ DIRECT_SINK: 分配大小受污点控制
│       └── [L5337-5389] 循环复制 payload_copy，使用 payload_offset 控制循环
└── [L5506] auth_hash_len + 12 + *((uint16_t *)packet_info + 5) 用于大小计算

packet_info[9-12] → selector_words[0-3] 🔴 TAINTED
├── [L5300] IPSECL_DBG_AhPktAlgo(..., selector_words[0], selector_words[1], &algo_dbg_word)
└── [L5463] IPSECL_DBG_AhPktAlgo(...)

packet_info[14] → algo_dbg_word 🔴 TAINTED

packet_info[32] → auth_header[0] 🔴 TAINTED
├── [L5423] *((uint8_t *)packet_info + 32) → auth_header[0]
└── [L5542] MBUF_CopyDataFromBufferToMBuf(..., packet_info[0], ..., auth_header, ...)

*((uint16_t *)packet_info + 5) → ip_header 字段写入
```

### 新导入的污点载体
| 对象 | 导入方式 | 行号 |
|------|----------|------|
| ip_header | MBUF_MakeMemoryContinuous_fl (packet_info[0] 作为大小参数) | L5248 |
| sa_entry | VOS_AVL3_Find (sa_lookup_key ← packet_info[3]) | L5269 |
| payload_copy | VRP_Malloc_F (payload_offset ← packet_info[4]-packet_info[0]) | L5340 |
| header_copy | VRP_Malloc_F (packet_info[0] 作为分配大小) | L5381 |
| auth_header | 从 packet_info 字段写入 | L5423, L5427 |
| selector_words | packet_info[9-12] → selector_words[0-3] | L5240-5243 |
| algo_dbg_word | packet_info[14] | L5297 |

---

## 污点终点汇总

### 📌 数据消费（读取污点数据）
| 位置 | 操作 | 说明 |
|------|------|------|
| L5261 | IPSEC_LIB_Ipv6AddrToStr(ip_header+8, ...) | 提取 IPv6 源地址 |
| L5262 | IPSEC_LIB_Ipv6AddrToStr(ip_header+24, ...) | 提取 IPv6 目的地址 |
| L5300 | IPSECL_DBG_AhPktAlgo(..., selector_words[0], ...) | 调试日志 |
| L5463 | IPSECL_DBG_AhPktAlgo(..., selector_words[0], ...) | 调试日志 |

### ⚠️ DIRECT_SINK（高危操作）
| 位置 | 操作 | 风险类型 |
|------|------|----------|
| L5248 | MBUF_MakeMemoryContinuous_fl(..., packet_info[0], ...) | 分配大小受污点控制 |
| L5323 | RAW_U8((void *)ip_header, packet_info[1]) = 51 | 污点索引写入，越界风险 |
| L5340 | VRP_Malloc_F(..., payload_offset, ...) | 分配大小受污点控制 |
| L5348 | MBUF_MakeMemoryContinuous_fl(..., read_offset, ...) | 偏移受污点控制 |
| L5373 | memcpy_s(payload_cursor, chunk_size, chunk_base, chunk_size) | 污点指针/长度 |
| L5381 | VRP_Malloc_F(..., packet_info[0], ...) | 分配大小受污点控制 |
| L5405 | MBUF_CopyDataFromMBufToBuffer(..., packet_info[0], header_copy) | 复制大小受污点控制 |
| L5467 | MBUF_CopyDataFromMBufToBuffer(..., packet_info[0], header_copy) | 复制大小受污点控制 |
| L5489 | algo_desc[7](auth_ctx, header_copy, packet_info[0]) | 长度参数受污点控制 |
| L5516 | MBUF_MakeMemoryContinuous_fl(..., auth_hash_len+12+packet_info[0], ...) | 总大小计算受污点影响 |
| L5526 | MBUF_CopyDataFromBufferToMBuf(..., packet_info[0], header_copy, ...) | 复制大小受污点控制 |
| L5542 | MBUF_CopyDataFromBufferToMBuf(..., packet_info[0], ..., auth_header, ...) | 偏移受污点控制，越界写入风险 |
| L5549 | MBUF_CopyDataFromBufferToMBuf 偏移 | 偏移受污点控制 |

---

## 新导入污点载体的下游传播

### header_copy 🔴 TAINTED
```
└── [L5405] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, packet_info[0], &header_copy)
    ├── [L5408] RAW_U32(header_copy, 0) → 提取字段值
    ├── [L5411] RAW_U32(header_copy, 0) = 0 → 修改字段
    ├── [L5447] RAW_U32(header_copy, 0) = saved_word0 → 恢复字段
    ├── [L5467] MBUF_CopyDataFromMBufToBuffer(..., packet_info[0], header_copy) ⚠️ 复制大小受污点
    ├── [L5489] algo_desc[7](auth_ctx, header_copy, packet_info[0]) ⚠️ 长度参数受污点
    ├── [L5526] MBUF_CopyDataFromBufferToMBuf(..., packet_info[0], header_copy, ...) ⚠️ 复制大小受污点
    └── [L5471] MBUF_CopyDataFromBufferToMBuf(mbuf, ..., header_copy, ...) → 写回 mbuf
```

### payload_copy 🔴 TAINTED
```
└── [L5340] VRP_Malloc_F(..., payload_offset, ...)
    └── [L5337-5389] 循环复制 payload_copy（payload_offset 控制循环次数）
        └── [L5373] memcpy_s(payload_cursor, chunk_size, chunk_base, chunk_size) ⚠️ DIRECT_SINK
```

### auth_header 🔴 TAINTED
```
└── [L5423] *((uint8_t *)packet_info + 32) → auth_header[0]
└── [L5427] RAW_U32(auth_header, 4) = packet_info[3]
    └── [L5542] MBUF_CopyDataFromBufferToMBuf(..., packet_info[0], ..., auth_header, ...) ⚠️ 偏移受污点
```

### sa_entry 🔴 TAINTED
```
└── [L5269] sa_entry = VOS_AVL3_Find(..., &sa_lookup_key, ...)
    └── 用于后续 SA 相关操作
```

---

## [32/61] RAW_U16  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `sa_lookup_key` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: RAW_U16

## 函数信息
- 文件: libipsec.c
- 功能: 16位数据写入工具函数（被sa_lookup_key构造过程调用）
- 上下文: 由调用者构造 SA 查找键时使用

## 污点源汇总

### INPUT-1: sa_lookup_key (uint64_t&) 🔴 TAINTED
- 来源: 由外部包数据 `packet_info[3]`（AH SPI）污染
- 说明: sa_lookup_key 在调用 RAW_U16 前已被 RAW_U32 写入污点数据

## 传播路径

### sa_lookup_key 🔴 TAINTED
```
├── [L5205] uint64_t sa_lookup_key = 0;               → 初始化为0（干净）
│
├── [L5267] RAW_U32(&sa_lookup_key, 0) = packet_info[3]; → 🔴 TAINTED
│   (packet_info[3] 包含网络报文的 SPI 值)
│
├── [L5268] RAW_U16(&sa_lookup_key, 4) = 51;          → 调用当前函数
│   (写入常量51到偏移4，sa_lookup_key 低32位仍为 🔴 TAINTED)
│
├── [L5269] VOS_AVL3_Find(..., &sa_lookup_key, ...) → 📎 子函数
│   (污染的 SA 标识符作为 AVL 树查找键)
│
├── [L5277] (unsigned int)sa_lookup_key               → 📌 USED（日志格式串）
│                                                        （用于调试输出）
│
├── [L5291] (unsigned int)sa_lookup_key               → 📌 USED（日志格式串）
│
└── [L5343] (unsigned int)sa_lookup_key               → 📌 USED（日志格式串）
```

## RAW_U16 在当前上下文的调用分析
| 调用位置 | 写入内容 | 地址参数 | 偏移参数 |
|---------|---------|---------|---------|
| L5268 | 51 (常量) | &sa_lookup_key | 4 |

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| sa_lookup_key | VOS_AVL3_Find | L5269 | 受污染的 SPI 值作为 AVL 树查找键 |
| sa_lookup_key | 日志输出 | L5277/L5291/L5343 | USED（日志格式串，调试用途） |

## DIRECT_SINK（函数内直接危险操作）
- **L5269** — `VOS_AVL3_Find(..., &sa_lookup_key, ...)`: 受污染的 SPI 值作为 AVL 树查找键，可能导致 SA 存在性探测或错误的 SA 选取

## 新引入的污点对象
无（RAW_U16 在此上下文中仅作为写操作，不产生新的污点载体）

---

## [33/61] IPSEC_LIB_Ipv6AddrToStr  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `ip_header` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIB_Ipv6AddrToStr

## 函数信息
- 文件: libipsec.c
- 行号: L7658-L7677
- 签名: `void IPSEC_LIB_Ipv6AddrToStr(void *addr_ptr, char *out_str)`

## 污点源 (继承自调用上下文)
- addr_ptr (void*) 🔴 TAINTED — 继承自 ip_header 外部网络数据包缓冲区指针
  - 调用点1: L5263 传入 `ip_header + 8` (IPv6 源地址字段)
  - 调用点2: L5264 传入 `ip_header + 24` (IPv6 目的地址字段)

## 传播路径

### addr_ptr 🔴 TAINTED (外部输入)
├── [L7673] memcpy_s(addr_words, 16, (const void *)addr_ptr, 16)
│   ⚠️ DIRECT_SINK: 从 ip_header+8 或 ip_header+24 读取 16 字节，源地址受污点控制
│   └── [L7675] addr_words[i] = __builtin_bswap16(addr_words[i])
│       └── addr_words[] 仍 🔴 TAINTED (字节序交换后污点仍保留)
│           └── [L7676] VOS_Inet_ntoa_b_ipv6(addr_words[0], addr_words[1], (char *)out_str)
│               📎 子函数: VOS_Inet_ntoa_b_ipv6
└── [L7676] 📌 USED (VOS_Inet_ntoa_b_ipv6 消费污点 addr_words)

## 数据流树状图

```
### INPUT: addr_ptr (void*) 🔴 TAINTED (继承自外部网络输入 ip_header)
├── [L5263] 调用点: ip_header+8 (IPv6源地址) → addr_ptr 🔴 TAINTED
├── [L5264] 调用点: ip_header+24 (IPv6目的地址) → addr_ptr 🔴 TAINTED
└── [L7673-L7676] 内部处理
    └── [L7673] memcpy_s 从污点指针读取 16 字节
        ⚠️ DIRECT_SINK: 指针偏移受 ip_header 污点控制
        └── [L7675] 字节序交换 → addr_words[] 仍 🔴 TAINTED
            └── [L7676] VOS_Inet_ntoa_b_ipv6(addr_words, out_str) → 📌 USED
```

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| addr_ptr | VOS_Inet_ntoa_b_ipv6 | L7676 | 16字节IPv6地址写入输出字符串 |
| addr_words[] | VOS_Inet_ntoa_b_ipv6 | L7676 | 字节序转换后仍为污点 |

## 新导入的污点对象
- **addr_words[16]** (uint16_t[16]): memcpy_s 从污点指针 addr_ptr 复制 16 字节后成为污点载体，在函数内部继续传播

## 安全摘要
⚠️ **核心风险**: addr_ptr 继承自外部网络数据包缓冲区 ip_header，偏移量 +8/+24 对应 IPv6 源/目的地址（网络输入完全可控）
- L7673: memcpy_s 从污点指针读取 16 字节到栈缓冲区 addr_words，指针偏移受污点控制
- L7675: __builtin_bswap16 字节序交换后污点状态仍保留
- L7676: 转换后的 IPv6 字符串写入 out_str，out_str 由调用者分配（65字节缓冲区）

---

## [34/61] RAW_U64  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: RAW_U64

## 函数信息
- 文件: libipsec.c
- 功能: 从 parse_state 缓冲区提取 64 位数据
- 签名: `uint64_t RAW_U64(uint8_t *parse_state, uint8_t offset)`

## 污点传播分析

### 输入参数
| 参数 | 类型 | 污点状态 | 来源 |
|------|------|----------|------|
| `parse_state` | uint8_t* | 🔴 TAINTED | 由 IPSEC_PKT_ParseAndVerifyHdr() 从网络 mbuf 填充 |
| `offset` | uint8_t | 🟢 CLEAN | 编译时常量 PST_DST6 + 0/8 |

### RAW_U64 函数行为
```
RAW_U64(parse_state, offset)
├── 从 parse_state[offset] 开始读取 8 字节
├── 组装为 uint64_t 返回值
└── 返回值 🔴 TAINTED (直接从污点缓冲区提取)
```

### 数据流树状图

#### INPUT-1: parse_state (uint8_t*) 🔴 TAINTED
```
parse_state 🔴 TAINTED [缓冲区来自外部网络数据]
│
├── [L10852] dst_filter_lo = RAW_U64(parse_state, PST_DST6 + 0)
│   └── dst_filter_lo 🔴 TAINTED
│       └── 用途: IPv6 地址低 64 位 (目标地址过滤)
│
├── [L10853] dst_filter_hi = RAW_U64(parse_state, PST_DST6 + 8)
│   └── dst_filter_hi 🔴 TAINTED
│       └── 用途: IPv6 地址高 64 位 (目标地址过滤)
│
├── [L11050] dst_filter_lo = RAW_U64(parse_state, PST_DST6 + 0)
│   └── dst_filter_lo 🔴 TAINTED (输入处理路径)
│
└── [L11051] dst_filter_hi = RAW_U64(parse_state, PST_DST6 + 8)
    └── dst_filter_hi 🔴 TAINTED (输入处理路径)
```

### RAW_U64 返回值安全分析

| 调用位置 | 偏移常量 | 缓冲区范围 | 状态 |
|----------|----------|------------|------|
| L10852, L11050 | PST_DST6 + 0 = 36 | parse_state[36-43] | ✅ 安全 |
| L10853, L11051 | PST_DST6 + 8 = 44 | parse_state[44-51] | ✅ 安全 |

- 偏移量 `PST_DST6 = 36` 为编译时常量，非攻击者可控
- 无缓冲区越界风险
- 无 DIRECT_SINK 风险

### 新导入的污点对象（RAW_U64 产生）

| 对象 | 类型 | 污点来源 | 用途 |
|------|------|----------|------|
| `dst_filter_lo` | uint64_t | RAW_U64(parse_state, PST_DST6+0) | IPv6 目标地址低 64 位过滤 |
| `dst_filter_hi` | uint64_t | RAW_U64(parse_state, PST_DST6+8) | IPv6 目标地址高 64 位过滤 |

### 接收此污点的子函数

| 函数 | 调用位置 | 接收的形参 |
|------|---------|------------|
| `IPSEC_PKT_ParseAndVerifyHdr` | L10832, L11030 | `packet_state` — 填充后成为污点载体 |
| `IPSEC_LIBI_GetManualSa` | L10855, L11053 | `manual_sa_cfg` — 使用网络派生的SPI/目的IP查找SA |
| `IPSEC_AH_HandleOutputPkt` | L10868 | `packet_info` — 使用网络派生的SPI/目的/协议处理输出 |
| `IPSEC_ESP_HandleOutputPkt` | L10897 | `packet_info` — 使用网络派生的SPI/目的/协议处理输出 |
| `IPSEC_AH_HandleInputPkt` | L11062 | `packet_info` — 使用网络头部字段处理输入 |
| `IPSEC_ESP_HandleInputPkt` | L11085 | `packet_info` — 使用网络头部字段处理输入 |

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| parse_state | IPSEC_PKT_ParseAndVerifyHdr | L10832, L11030 | 解析后成为完整污点载体 |
| parse_state | IPSEC_LIBI_GetManualSa | L10855, L11053 | 使用网络派生的SPI/目的IP |
| parse_state | IPSEC_AH_HandleOutputPkt | L10868 | 使用网络头部字段处理输出 |
| parse_state | IPSEC_ESP_HandleOutputPkt | L10897 | 使用网络头部字段处理输出 |
| parse_state | IPSEC_AH_HandleInputPkt | L11062 | 使用网络头部字段处理输入 |
| parse_state | IPSEC_ESP_HandleInputPkt | L11085 | 使用网络头部字段处理输入 |
| RAW_U64 返回值 | dst_filter_lo | L10852, L11050 | 目标IPv6地址低64位 |
| RAW_U64 返回值 | dst_filter_hi | L10853, L11051 | 目标IPv6地址高64位 |

---

## [35/61] IPSEC_Print_File  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_Print_File

## 函数信息
- 文件: libipsec.c
- 签名: `void IPSEC_Print_File(int64_t ctx, int flag, const char *text)`

## 污点源

| 参数 | 类型 | 污点状态 | 来源 |
|------|------|---------|------|
| ctx | int64_t | 🔴 TAINTED | 外部指针参数 a1 |

## 新导入的污点对象

无

## 传播路径

### ctx 🔴 TAINTED
```
[L19776] (void)ctx;
         └── 立即转换为void，无任何操作
         └── 无派生变量
         └── 无子函数调用
         └── 无sink触发
```
→ 函数结束，污点未使用

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| ctx | DISCARDED | L19776 | (void)ctx 立即丢弃，无数据流 |

## 接收此污点的子函数

无

## 备注

`IPSEC_Print_File` 是一个桩函数，空实现：

```c
void IPSEC_Print_File(int64_t ctx, int flag, const char *text)
{
    (void)ctx;
    (void)flag;
    (void)text;
}
```

污点参数 `ctx` 在函数内被立即丢弃，未被解引用、拷贝或传递到任何下游操作。无数据流。

---

## [36/61] IPSEC_MakeDbgCompStrSetter  ·  被跟入函数

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

---

## [37/61] IPSECL_PKT_GetAuthHaslen  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `algo_desc` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSECL_PKT_GetAuthHaslen

## 函数信息
- 文件: libipsec.c
- 行号: L11928-L11946
- 签名: `ReturnType IPSECL_PKT_GetAuthHaslen(int algo_desc, ...)`

## 污点源
| 变量 | 类型 | 状态 | 说明 |
|------|------|------|------|
| algo_desc | int | 🔴 TAINTED | 外部输入，调用者传入的算法描述符 |

## 新导入的污点对象
无

## 传播路径

### INPUT-1: algo_desc (int) 🔴 TAINTED
```
├── [L11928] if (auth_algo == 3) → 🔴 TAINTED（条件分支控制）
│   └── [L11929] *out_len = 16 → 🟢 CLEANED（常量赋值）
│   └── [L11930] return 0 → ⚠️ CONTROL_FLOW_DEPENDENT
│
├── [L11931] if (auth_algo <= 3) → 🔴 TAINTED
│   └── [L11933] if (auth_algo >= 1)
│       └── [L11934] *out_len = 12 → 🟢 CLEANED
│       └── [L11935] return 0 → ⚠️ CONTROL_FLOW_DEPENDENT
│       └── [L11943] return 0 → ⚠️ CONTROL_FLOW_DEPENDENT
│
├── [L11937] if (auth_algo != 4) → 🔴 TAINTED
│   └── [L11939] if (auth_algo == 5)
│       └── [L11940] *out_len = 32 → 🟢 CLEANED
│       └── [L11941] return 0 → ⚠️ CONTROL_FLOW_DEPENDENT
│       └── [L11942] return 0 → ⚠️ CONTROL_FLOW_DEPENDENT
│
└── [L11945] *out_len = 24 → 🟢 CLEANED（默认case）
└── [L11946] return 0 → ⚠️ CONTROL_FLOW_DEPENDENT
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|-----------|
| — | — | — |

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| algo_desc | *out_len 写入 | L11929, L11934, L11940, L11945 | 控制流依赖：输出长度值取决于污点算法描述符 |
| algo_desc | return value | L11930, L11935, L11941, L11942, L11943, L11946 | 控制流依赖：返回值取决于污点算法描述符 |

## 安全分析备注
- 污点数据 `algo_desc` 仅用于条件分支控制，不直接写入输出缓冲区
- `*out_len` 接收的是常量值（12/16/24/32），由污点控制的条件分支选择
- 不存在直接缓冲区溢出风险，但存在逻辑漏洞风险：若算法描述符非法，可能导致默认值被错误使用

---

## [38/61] IPSEC_SADB_UpdateSaStats  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `sadb_entry` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SADB_UpdateSaStats

## 函数信息
- 文件: libipsec.c
- 行号: L15388-L15460
- 签名: `int IPSEC_SADB_UpdateSaStats(int result, uint32_t *a2, int a3, int a4)`

## 污点源
| 参数 | 类型 | 状态 | 说明 |
|------|------|------|------|
| sadb_entry (a2) | uint32_t* | 🔴 TAINTED | 外部 SA 数据库条目指针，源自网络数据 |

## 新导入的污点对象
| 对象 | 类型 | 导入方式 | 说明 |
|------|------|----------|------|
| (无) | - | - | 本函数未调用 Recv/Read/Get/Decode 等输入函数 |

## 传播路径

### INPUT: sadb_entry (a2) 🔴 TAINTED
```
├── [L15391] case 1:  if (a2) ++a2[996]              ─── 📌 USED (counter inc, fixed idx 996)
├── [L15396] case 3:  if (a2) ++a2[998]              ─── 📌 USED (counter inc, fixed idx 998)
├── [L15400] case 4:  if (a2) ++a2[999]              ─── 📌 USED (counter inc, fixed idx 999)
├── [L15404] case 5:  if (a2) ++a2[1000]             ─── 📌 USED (counter inc, fixed idx 1000)
├── [L15408] case 7:  if (a2) ++a2[1002]              ─── 📌 USED (counter inc, fixed idx 1002)
├── [L15412] case 9:  if (a2) ++a2[1004]              ─── 📌 USED (counter inc, fixed idx 1004)
├── [L15398] case 2,6,8: ─── IPSEC_SADB_UpdateAuthFailStats(result, a2, a3)
│   └── 污点 a2 传入子函数
├── [L15429] case 0x14: if (a2) ++a2[1015]           ─── 📌 USED (counter inc, fixed idx 1015)
├── [L15441] case 0x18: if (a2) ++a2[1019]           ─── 📌 USED (counter inc, fixed idx 1019)
├── [L15438] case 0xA..0x13, 0x15, 0x16, 0x19, 0x1A: ─── IPSEC_SADB_UpdateInOutPktStats(result, a2, a3, a4)
│   └── 污点 a2 传入子函数
│   └── ⚠️ 注意: case 0x15(21) 时 a4 写入 a2[1016]; case 0x16(22) 时 a4 写入 a2[1017]
├── [L15442] case 0x17, 0x1B: ─── IPSEC_SADB_UpdatePktLenStats(result, a2, a3)
│   └── 污点 a2 传入子函数
├── [L15445] case 0x1C: ─── sub_2F794(result, a2)
│   └── 污点 a2 传入子函数
├── [L15449] case 0x1D: if (a2) ++a2[1024]           ─── 📌 USED (counter inc, fixed idx 1024)
└── [default] return result                          ─── 📌 USED (返回指针值)
```

## ⚠️ DIRECT_SINK
| 位置 | 操作 | 说明 |
|------|------|------|
| L15294 (callee 内) | `a2[1016] += a4` | 污点 a4（来自网络包数据）写入 sadb_entry 缓冲区，case 0x15(21) |
| L15296 (callee 内) | `a2[1017] += a4` | 污点 a4（来自网络包数据）写入 sadb_entry 缓冲区，case 0x16(22) |

**说明**: 当调用方传入的 a4 由网络数据派生且 a3 选中 case 0x15 或 0x16 时，污点 a4 被写入 sadb_entry 结构体的计数器字段，造成统计值篡改。索引为硬编码（固定偏移），但写入的值受污点控制。

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| sadb_entry (a2) | 📌 USED | L15391, L15396, L15400, L15404, L15408, L15412 | 计数器增量操作（固定索引 996, 998, 999, 1000, 1002, 1004）|
| sadb_entry (a2) | 📌 USED | L15429, L15441, L15449 | 计数器增量操作（固定索引 1015, 1019, 1024）|
| sadb_entry (a2) | 📎 CALLEE | L15398 | 传入 IPSEC_SADB_UpdateAuthFailStats(result, a2, a3) |
| sadb_entry (a2) | 📎 CALLEE | L15438 | 传入 IPSEC_SADB_UpdateInOutPktStats(result, a2, a3, a4) |
| sadb_entry (a2) | 📎 CALLEE | L15442 | 传入 IPSEC_SADB_UpdatePktLenStats(result, a2, a3) |
| sadb_entry (a2) | 📎 CALLEE | L15445 | 传入 sub_2F794(result, a2) |

## 跟入子函数汇总
| 序号 | 文件 | 函数 | 行号 | 接收参数 | 说明 |
|------|------|------|------|----------|------|
| 1 | libipsec.c | IPSEC_SADB_UpdateAuthFailStats | L15398 | result, a2, a3 | 更新认证失败统计 |
| 2 | libipsec.c | IPSEC_SADB_UpdateInOutPktStats | L15438 | result, a2, a3, a4 | 更新入出包统计 |
| 3 | libipsec.c | IPSEC_SADB_UpdatePktLenStats | L15442 | result, a2, a3 | 更新包长度统计 |
| 4 | libipsec.c | sub_2F794 | L15445 | result, a2 | 未知函数 |

---

## [39/61] IPSEC_LIB_Ipv4AddrToStr  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `ip_header` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIB_Ipv4AddrToStr

## 函数信息
- **文件**: `core/ipsec/libipsec.c`
- **行号**: L7682–L7697
- **签名**: `int64_t IPSEC_LIB_Ipv4AddrToStr(int64_t addr, int64_t out_str, int out_len)`

## 污点源
| 变量 | 类型 | 说明 |
|------|------|------|
| `ip_header` | 🔴 TAINTED | 网络数据包缓冲区， callers 通过 `RAW_U32(ip_header, 12/16)` 提取 IPv4 源/目的地址字段后作为 `addr` 参数传入 |
| `addr` | 🔴 TAINTED | 形参， callers 传入的 `RAW_U32(ip_header, 12)` 或 `RAW_U32(ip_header, 16)` 的结果 |

## 新导入的污点对象
| 变量 | 类型 | 说明 |
|------|------|------|
| `ipv4` | 🔴 TAINTED | L7684 由 `addr` 直接赋值，继承污点 |
| `result` | 🔴 TAINTED | L7685 由 `addr` 直接赋值，继承污点 |
| `out_str` | 🔴 TAINTED carrier | 形参，作为输出缓冲区传入 callers 的 `src_addr_text`/`dst_addr_text`，由 `VOS_IpAddrToStr` 写入格式化的 IP 字符串后承载污点数据 |

## 传播路径

```
### INPUT-1: addr (int64_t) 🔴 TAINTED
├── [L7684] ipv4 = (unsigned int)addr → ipv4 🔴 TAINTED
├── [L7685] result = addr → result 🔴 TAINTED
├── [L7686] if (out_len != 0)
│   ├── [L7687] if (out_str == 0)
│   │   └── [L7689] return result → 🟢 CLEANED (整型状态码)
│   └── [L7690] return VOS_IpAddrToStr(__builtin_bswap32(ipv4), out_str)
│               ├─ ipv4 🔴 TAINTED → VOS_IpAddrToStr 第1参数
│               └─ out_str 🔴 TAINTED carrier → VOS_IpAddrToStr 第2参数
│                   📎 见跟入列表 (VOS_IpAddrToStr)
└── [L7692] result = VRP_Assert(...) → result 🟢 CLEANED (assert 返回值)
    ├── [L7693] if (out_str != 0)
    │   └── [L7695] return VOS_IpAddrToStr(__builtin_bswap32(ipv4), out_str)
    │               ├─ ipv4 🔴 TAINTED → VOS_IpAddrToStr 第1参数
    │               └─ out_str 🔴 TAINTED carrier → VOS_IpAddrToStr 第2参数
    │                   📎 见跟入列表 (VOS_IpAddrToStr)
    └── [L7696] return result → 🟢 CLEANED
```

## ⚠️ DIRECT_SINK（直接危险操作）

| 位置 | 操作 | 风险描述 |
|------|------|----------|
| L6206/6207, L6767/6768, L8811/8812 | `RAW_U32((void *)ip_header, 12/16)` | 从网络包缓冲区在固定结构偏移量处读取 4 字节 IPv4 地址；若 `ip_header` 未做包长度边界校验，可能越界读取超过实际包数据长度 |
| L9860/9861, L11249/11250 | `RAW_U32(ip_header, 12/16)` | 同上，读取源/目的 IPv4 地址 |

> 注：偏移量 12/16 是编译时常量（IPv4 头结构中 SrcAddr/DstAddr 的固定位置），指针运算本身未受污点控制；残余风险为 `ip_header` 基指针在调用前未充分校验包实际长度。

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `addr` / `ipv4` | `VOS_IpAddrToStr` | L7690, L7695 | 经字节序转换后作为 IP 地址参数，外部库处理 |
| `out_str` | `VOS_IpAddrToStr` | L7690, L7695 | 作为输出缓冲区，函数向其写入格式化 IP 字符串 |
| `result` | return | L7689, L7696 | 整型状态码，🟢 CLEANED |

## 跟入列表（子函数）

| 文件 | 函数 | 调用行 | 接收的形参 |
|------|------|--------|------------|
| - | `VOS_IpAddrToStr` | L7690, L7695 | `__builtin_bswap32(ipv4)`, `out_str` |

> `VOS_IpAddrToStr` 为外部库函数（标记 🟡 EXPORT）。

---

## [40/61] IPSEC_ESP_HandleOutputPkt  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `parse_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_ESP_HandleOutputPkt

## 函数信息
- 文件: `libipsec.c`
- 签名: `IPSEC_ESP_HandleOutputPkt(int a, int b, unsigned int *parse_state, void *mbuf, void *c, void *d)`

---

## 污点源

| 标识 | 变量 | 类型 | 说明 |
|------|------|------|------|
| INPUT-1 | `mbuf` | `void*` | 🔴 TAINTED — 外部网络数据包缓冲区（ESP outbound packet） |
| INPUT-2 | `parse_state` | `unsigned int*` | 🔴 TAINTED — 外部指针，被强转为 `packet_info` 使用 |

---

## 污点传播树状图

### INPUT-1: `mbuf` (void*) 🔴 TAINTED
```
├── [L8368] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...)
│   → ip_header 🔴 TAINTED (新导入对象)
│   ├── [L8470] RAW_U8((void*)ip_header, packet_info[1]) = 50
│   └── [L8474] RAW_U16((void*)ip_header, 4) = ...
│
├── [L8491] appended_tail = (uint8_t*)MBUF_AppendMemorySpace_fl(mbuf, auth_and_tail_len, ...)
│   → appended_tail 🔴 TAINTED (新导入对象)
│   ├── [L8500] appended_tail[copy_offset] = (uint8_t)(copy_offset + 1)
│   ├── [L8501] appended_tail[pad_len] = (uint8_t)(tail_len - 2)
│   ├── [L8502] appended_tail[pad_len + 1] = *((uint8_t*)packet_info + 32)
│   └── [L8721] memcpy_s(appended_tail + tail_len, auth_hash_len, auth_result, auth_hash_len)
│       └── appended_tail 作为 memcpy 目标，接收干净数据
│
├── [L8551] chunk = MBUF_MakeMemoryContinuous_fl(mbuf, copy_offset, copy_len, ...) [循环]
│   → chunk 🔴 TAINTED (新导入对象)
│   ├── [L8560] block_ptr = (uint8_t*)chunk
│   │   → block_ptr 🔴 TAINTED (新导入对象)
│   │   ├── [L8565] callback(sa_entry, block_ptr, copy_len)
│   │   │   └── ⚠️ DIRECT_SINK: copy_len 来自 packet_info[6]（外部输入）
│   │   ├── [L8566-L8567] auth_desc[7](auth_ctx, block_ptr, enc_block_size)
│   │   └── [L8569] memcpy_s((void*)(sa_entry+80), 16, block_ptr, iv_len)
│   │       └── ⚠️ DIRECT_SINK: block_ptr 来自 mbuf-derived chunk，iv_len 来自 SA 字段
│   └── [L8589] auth_desc[7](auth_ctx, (const void*)chunk, copy_len)
│
├── [L8698] MBUF_PrependMemorySpace_fl(mbuf, iv_len + 8, ...)
│   └── ⚠️ DIRECT_SINK: 扩展大小参数 iv_len 来自污点关联的 SA 字段
│
├── [L8704] MBUF_MakeMemoryContinuous_fl(mbuf, 0, iv_len + 8 + *packet_info, ...)
│   └── ⚠️ DIRECT_SINK: 内存连续化大小包含污点 iv_len 和 *packet_info
│
├── [L8709] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, *packet_info, scratch_buf)
│   → mbuf 作为源参数（读取数据）
│
├── [L8713] MBUF_PrependMemorySpace_fl(mbuf, iv_len + 8, ...)
│   └── ⚠️ DIRECT_SINK: 扩展大小参数 iv_len 来自污点关联的 SA 字段
│
├── [L8719] MBUF_MakeMemoryContinuous_fl(mbuf, 0, iv_len + 8 + *packet_info, ...)
│   └── ⚠️ DIRECT_SINK: 内存连续化大小包含污点 iv_len 和 *packet_info
│
├── [L8722] MBUF_CopyDataFromBufferToMBuf(mbuf, 0, *packet_info, scratch_buf, ...)
│   → mbuf 作为目标参数（接收干净数据）
│
└── [L8726] MBUF_CopyDataFromBufferToMBuf(mbuf, *packet_info, iv_len + 8, &esp_hdr[0], ...)
    └── ⚠️ DIRECT_SINK: 写入偏移 *packet_info 和长度 iv_len+8 都由外部输入/SA 控制
```

---

### INPUT-2: `parse_state` → `packet_info` (unsigned int*) 🔴 TAINTED
```
├── [L8374] selector_pair = ((uint64_t)packet_info[10]<<32) | packet_info[9] → selector_pair 🔴 TAINTED (新导入对象)
│   └── [L8417] VOS_AVL3_Find(..., &selector_pair_hi, ...)
│       ├── [L8438] IPSEC_PKT_DebugPacket(..., selector_pair, ...)
│       ├── [L8440] IPSEC_PKT_DebugPacket(..., selector_pair, ...)
│       ├── [L8629] IPSEC_PKT_DebugPacket(..., selector_pair, ...)
│       └── [L8708] IPSEC_PKT_DebugPacket(..., selector_pair, ...)
│
├── [L8375] selector_pair_hi = ((uint64_t)packet_info[12]<<32) | packet_info[11] → selector_pair_hi 🔴 TAINTED (新导入对象)
│   ├── [L8405] RAW_U32(&selector_pair_hi,0) = packet_info[3]
│   └── [L8417] VOS_AVL3_Find(..., &selector_pair_hi, ...) → 📎 见跟入列表
│
├── [L8368] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...)
│   └── ⚠️ DIRECT_SINK: *packet_info 控制内存分配大小
│
├── [L8442] algo_dbg_word = packet_info[14] → algo_dbg_word 🔴 TAINTED (新导入对象)
│   ├── [L8443] IPSECL_DBG_EspPktAlgo(..., &algo_dbg_word) → 📎 见跟入列表
│   └── [L8450] IPSECL_DBG_EspPktAlgo(..., &algo_dbg_word) → 📎 见跟入列表
│
├── [L8457] payload_len = packet_info[4] → payload_len 🔴 TAINTED
├── [L8458] payload_offset = payload_len - *packet_info → payload_offset 🔴 TAINTED
├── [L8459] packet_info[5] = payload_offset → packet_info[5] 🔴 TAINTED
├── [L8444] enc_block_size = RAW_U16(enc_desc, 12) → enc_block_size 🔴 TAINTED
├── [L8460] pad_len = ... % enc_block_size → pad_len 🔴 TAINTED (依赖污点 payload_offset)
│   └── [L8509-8512] for(copy_offset=0; copy_offset<pad_len; ...) appended_tail[copy_offset]
│       └── ⚠️ DIRECT_SINK: 循环边界来自污点 pad_len
├── [L8461] tail_len = pad_len + 2 → tail_len 🔴 TAINTED
│   └── [L8511] appended_tail[pad_len] = (uint8_t)(tail_len - 2)
│   └── [L8512] appended_tail[pad_len + 1] = *((uint8_t*)packet_info + 32)
│       └── ⚠️ DIRECT_SINK: 污点 tail_len 控制下标
├── [L8462] auth_and_tail_len = auth_hash_len + tail_len → auth_and_tail_len 🔴 TAINTED
├── [L8463] new_packet_len = payload_len + iv_len + 8 + auth_and_tail_len → new_packet_len 🔴 TAINTED
├── [L8464] *((uint8_t*)packet_info + 29) = (uint8_t)tail_len → packet_info[29] 🔴 TAINTED
├── [L8465] packet_info[6] = iv_len + 8 + payload_offset + tail_len → packet_info[6] 🔴 TAINTED
│   ├── [L8549] copy_len = packet_info[6] - iv_len - 8 - auth_hash_len - processed → copy_len 🔴 TAINTED
│   │   └── [L8551] chunk = MBUF_MakeMemoryContinuous_fl(mbuf, copy_offset, copy_len, ...)
│   │       └── ⚠️ DIRECT_SINK: 污点 copy_len 控制内存块大小
│   └── [L8562] 循环遍历 chunk 加密 auth
│
├── [L8445] *((uint8_t*)packet_info + 30) = RAW_U16(sa_entry, 28) → packet_info[30] 🔴 TAINTED
├── [L8446] *((uint8_t*)packet_info + 31) = enc_block_size → packet_info[31] 🔴 TAINTED
│
├── [L8514] esp_hdr[0] = __builtin_bswap32(packet_info[3]) → esp_hdr[0] 🔴 TAINTED (新导入对象)
│   └── [L8528] auth_desc[7](auth_ctx, &esp_hdr[0], iv_len+8)
│
├── [L8537] copy_offset = *packet_info → copy_offset 🔴 TAINTED
│   └── [L8551] MBUF_MakeMemoryContinuous_fl(mbuf, copy_offset, copy_len, ...)
│       └── ⚠️ DIRECT_SINK: 污点 copy_offset 控制内存读取起点
│
├── [L8628] scratch_buf = VRP_Malloc_F(..., *packet_info, ...)
│   └── ⚠️ DIRECT_SINK: *packet_info 污点大小控制堆分配
├── [L8644] scratch_buf = VRP_Malloc_F(..., *packet_info, ...)
│   └── ⚠️ DIRECT_SINK: *packet_info 污点大小控制堆分配
│
├── [L8663] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, *packet_info, scratch_buf)
│   └── ⚠️ DIRECT_SINK: *packet_info 污点大小控制复制字节数
├── [L8688] MBUF_MakeMemoryContinuous_fl(mbuf, 0, iv_len + 8 + *packet_info, ...)
│   └── ⚠️ DIRECT_SINK: *packet_info 参与总大小计算
├── [L8699] MBUF_CopyDataFromBufferToMBuf(mbuf, 0, *packet_info, scratch_buf, ...)
│   └── ⚠️ DIRECT_SINK: *packet_info 污点大小控制复制
└── [L8700] MBUF_CopyDataFromBufferToMBuf(mbuf, *packet_info, iv_len + 8, &esp_hdr[0], ...)
    └── ⚠️ DIRECT_SINK: *packet_info 污点偏移控制写入位置
```

---

## 新导入的污点载体对象（在当前函数内派生）

| 变量名 | 派生位置 | 派生来源 | 说明 |
|--------|---------|---------|------|
| `ip_header` | L8368 | `MBUF_MakeMemoryContinuous_fl()` 返回 | 🔴 TAINTED |
| `appended_tail` | L8491 | `MBUF_AppendMemorySpace_fl()` 返回 | 🔴 TAINTED |
| `chunk` | L8551 | `MBUF_MakeMemoryContinuous_fl()` 返回（循环内） | 🔴 TAINTED |
| `block_ptr` | L8560 | `(uint8_t*)chunk` 派生 | 🔴 TAINTED |
| `selector_pair` | L8374 | `packet_info[10,9]` 组合 | 🔴 TAINTED |
| `selector_pair_hi` | L8375 | `packet_info[12,11]` 组合 | 🔴 TAINTED |
| `algo_dbg_word` | L8442 | `packet_info[14]` 提取 | 🔴 TAINTED |
| `esp_hdr[0]` | L8514 | `bswap32(packet_info[3])` | 🔴 TAINTED |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `mbuf` | MBUF_MakeMemoryContinuous_fl | L8368 | 控制 mbuf 数据区域访问 |
| `mbuf` | MBUF_AppendMemorySpace_fl | L8491 | ESP padding 数据写入 |
| `mbuf` | MBUF_MakeMemoryContinuous_fl | L8551 | 数据加密处理（copy_len 受控） |
| `mbuf` | MBUF_PrependMemorySpace_fl | L8698 | prepend 大小 iv_len+8 可控 |
| `mbuf` | MBUF_MakeMemoryContinuous_fl | L8704 | 内存连续化大小可控 |
| `mbuf` | MBUF_CopyDataFromBufferToMBuf | L8726 | 写入位置和大小受污点控制 |
| `packet_info[1]` | RAW_U8 | L8476 | IP 头字段写入偏移受控 |
| `pad_len` | appended_tail[...] 循环 | L8509-8512 | padding 写入循环边界可控 |
| `packet_info[3]` | esp_hdr[0] = bswap32(...) | L8514 | ESP SPI 字段写入 |
| `copy_len` | MBUF_MakeMemoryContinuous_fl | L8551 | 内存块大小受控 |
| `*packet_info` | VRP_Malloc_F | L8628, L8644 | 堆分配大小可控 |
| `*packet_info` | MBUF_CopyDataFromMBufToBuffer | L8663 | 数据复制大小可控 |
| `*packet_info` | MBUF_CopyDataFromBufferToMBuf | L8699, L8700 | 数据复制大小/偏移可控 |

---

## 关键 DIRECT_SINK 汇总

| 行号 | 危险操作 | 污点来源 |
|------|---------|---------|
| L8476 | `RAW_U8((void*)ip_header, packet_info[1]) = 50` | `packet_info[1]` 污点下标 |
| L8509-8512 | `appended_tail[copy_offset/pad_len+1]` 循环写入 | `pad_len` 来自污点 `payload_offset` |
| L8514 | `esp_hdr[0] = bswap32(packet_info[3])` | `packet_info[3]` 污点 SPI 写入数据包头 |
| L8551 | `MBUF_MakeMemoryContinuous_fl(..., copy_len, ...)` | `copy_len` 来自 `packet_info[6]` |
| L8628, L8644 | `VRP_Malloc_F(..., *packet_info, ...)` | `*packet_info` 控制堆分配大小 |
| L8663 | `MBUF_CopyDataFromMBufToBuffer(..., *packet_info, ...)` | `*packet_info` 控制复制大小 |
| L8699 | `MBUF_CopyDataFromBufferToMBuf(..., *packet_info, ...)` | `*packet_info` 控制复制大小 |
| L8700 | `MBUF_CopyDataFromBufferToMBuf(mbuf, *packet_info, ...)` | `*packet_info` 作为目标偏移量 |
| L8688 | `MBUF_MakeMemoryContinuous_fl(..., iv_len+8+*packet_info, ...)` | `*packet_info` 参与总大小计算 |

---

## [41/61] __builtin_bswap16  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `addr_words` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: __builtin_bswap16

## 函数信息
- 文件: libipsec.c
- 调用位置: L7671 (循环内)
- 签名: `uint16_t __builtin_bswap16(uint16_t)`

## 污点源
- addr_words 🔴 TAINTED — 从外部 addr_ptr 经 memcpy_s 导入网络数据 (L7670)

## 数据流树状图

### INPUT-1: ((uint16_t*)addr_words)[i] (uint16_t&) 🔴 TAINTED
├── [L7671] ret = __builtin_bswap16(((uint16_t*)addr_words)[i]) → ret 🔴 TAINTED
│   └── ⚠️ DIRECT_SINK: 编译器builtin对tainted buffer进行字节交换
├── [L7671] ((uint16_t*)addr_words)[i] = ret → addr_words[i] 🔴 TAINTED
│   └── 🟢 回写操作，标记为sink但不影响污点状态
└── [L7672] VOS_Inet_ntoa_b_ipv6(addr_words[0], addr_words[1], out_str) → 📌 USED

### INPUT-2: addr_words[0] (uint64_t) 🔴 TAINTED
└── [L7672] VOS_Inet_ntoa_b_ipv6(addr_words[0], addr_words[1], out_str) → 📌 USED

### INPUT-3: addr_words[1] (uint64_t) 🔴 TAINTED
└── [L7672] VOS_Inet_ntoa_b_ipv6(addr_words[0], addr_words[1], out_str) → 📌 USED

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| ((uint16_t*)addr_words)[i] | __builtin_bswap16 | L7671 | 编译器builtin字节交换处理 |
| addr_words[0], addr_words[1] | VOS_Inet_ntoa_b_ipv6 | L7672 | 作为IPv6地址输出参数 |

---

## [42/61] sub_2F794  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `a2` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: sub_2F794

## 函数信息
- 文件: libipsec.c
- 行号: L15470-L15474 (推测范围)
- 签名: `void sub_2F794(int64_t a2)`

## 污点源

### INPUT-1: a2 (int64_t) 🔴 TAINTED
外部指针参数，来源于调用者传入的脏数据（网络输入上下文）。

## 传播路径

```
a2 (int64_t) 🔴 TAINTED
├── [L15472] if (a2) → guard check
│   └── 🟢 CLEANED: 仅用于空指针判断，未传播污点
└── [L15473] ++RAW_U32((void*)a2, 4092) → 🟢 SAFE_DEREF
    ├── offset=4092 为编译时常量，非污点数据
    ├── 操作：++*(uint32_t*)(a2+4092)，值增量后未再作为地址/大小/下标使用
    └── ⚠️ DIRECT_SINK: 无 — 偏移量固定，无污点控制的指针/大小/下标
```

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| a2 | SAFE_DEREF | L15473 | 偏移量4092为常量，原子增量操作无二次传播 |

## 新导入的污点对象

无新污点对象在本函数中产生。

## 接收此污点的子函数

| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| （无） | — | — |

RAW_U32 为宏展开，非子函数调用；函数体无其他子函数调用。

---

## [43/61] IPSEC_LIB_GetLocalTime  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `out_str` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIB_GetLocalTime

## 函数信息
- 文件: core/ipsec/libipsec.c
- 行号: L7749-L7832
- 签名: `int64_t IPSEC_LIB_GetLocalTime(int64_t seconds, uint8_t *out_str, uint32_t *dst_flag_out)`

## 外部输入参数(已污染)
| 参数 | 类型 | 说明 |
|------|------|------|
| out_str | uint8_t * | 🔴 TAINTED — 外部输入参数，输出缓冲区指针 |

## 数据流树状图

### INPUT: out_str 🔴 TAINTED
├── [L7779] IPSEC_NvsPrintfStrSetter(out_str, 24, format, ...) → 写入格式化时间字符串到 out_str
│   └── out_str 🔴 TAINTED（内容由函数填充）
│
├── [L7784] base_len = VOS_StrLen((const char *)out_str) → base_len 🔴 TAINTED（由 out_str 内容派生）
│   │
│   ├── [L7789] 分支 cmp_result==3: out_str[base_len] = '-' → ⚠️ DIRECT_SINK
│   │   └── 数组下标受污点内容(base_len)控制
│   │
│   ├── [L7791] IPSEC_NvsPrintfStrSetter(&out_str[base_len + 1], 31, ...)
│   │   └── 接收污点子区域 &out_str[base_len+1] → 📎 子函数
│   │
│   ├── [L7795] 分支 cmp_result==3: out_str[VOS_StrLen((const char *)out_str)] = 0
│   │   └── ⚠️ DIRECT_SINK: 再次依赖污点内容计算下标
│   │
│   ├── [L7799] 分支 cmp_result==1: out_str[base_len] = '+' → ⚠️ DIRECT_SINK
│   │   └── 数组下标受污点内容(base_len)控制
│   │
│   ├── [L7801] 分支 cmp_result==1: IPSEC_NvsPrintfStrSetter(&out_str[base_len + 1], 31, ...)
│   │   └── 接收污点子区域 &out_str[base_len+1] → 📎 子函数
│   │
│   └── [L7807] 分支 cmp_result==1: out_str[VOS_StrLen((const char *)out_str)] = 0
│       └── ⚠️ DIRECT_SINK: 再次依赖污点内容计算下标
│
└── [L7812] 默认路径: out_str[base_len] = 0 → ⚠️ DIRECT_SINK

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| out_str | ⚠️ DIRECT_SINK | L7789, L7799, L7812 | 数组下标 out_str[base_len] 受污点内容控制 |
| out_str | ⚠️ DIRECT_SINK | L7795, L7807 | 数组下标依赖污点内容计算(VOS_StrLen) |

## 跟入的子函数列表
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| IPSEC_NvsPrintfStrSetter | L7779 | out_str |
| IPSEC_NvsPrintfStrSetter | L7791 | &out_str[base_len + 1] |
| IPSEC_NvsPrintfStrSetter | L7801 | &out_str[base_len + 1] |

## 安全风险分析
1. **污点偏移指针运算**: `&out_str[base_len + 1]` 的地址计算依赖污点内容
2. **重复直接Sink**: 多处 `out_str[base_len]` 赋值直接使用污点派生的下标
3. **下标计算链**: `VOS_StrLen((const char *)out_str)` 再次基于已污染内容计算下标

---

## [44/61] IPSEC_SADB_UpdateAuthFailStats  ·  被跟入函数

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

---

## [45/61] IPSEC_SADB_UpdateInOutPktStats  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `a2` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `a3` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `a4` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SADB_UpdateInOutPktStats

## 函数信息
- 文件: libipsec.c
- 行号: L15268-L15324
- 签名: `int IPSEC_SADB_UpdateInOutPktStats(uint32_t *a2, unsigned int a3, int a4)`

## 污点源

| ID | 参数名 | 类型 | 污点等级 | 说明 |
|----|--------|------|----------|------|
| INPUT-1 | a2 | uint32_t* | 🔴 TAINTED | 外部指针参数,指向统计数组缓冲区 |
| INPUT-2 | a3 | unsigned int | 🔴 TAINTED | 外部输入参数,用于条件分支判断 |
| INPUT-3 | a4 | int | 🔴 TAINTED | 外部输入参数,用于累加到统计数组 |

## 数据流树状图

### INPUT-1: a2 (uint32_t*) 🔴 TAINTED
```
a2 🔴 TAINTED
├── [L15269] if (a2) ++a2[1011]  → a2[1011] 🔴 TAINTED write
├── [L15272] if (a2) ++a2[1007]  → a2[1007] 🔴 TAINTED write
├── [L15274] if (a2) ++a2[1005]  → a2[1005] 🔴 TAINTED write
├── [L15276] if (a2) ++a2[1006]  → a2[1006] 🔴 TAINTED write
├── [L15281] if (a2) ++a2[1009]  → a2[1009] 🔴 TAINTED write
├── [L15284] if (a2) ++a2[1010]  → a2[1010] 🔴 TAINTED write
├── [L15286] if (a2) ++a2[1008]  → a2[1008] 🔴 TAINTED write
├── [L15289] if (a2) a2[1016] += a4  → a2[1016] 🔴 TAINTED write (合并a4)
├── [L15294] if (a2) ++a2[1020]  → a2[1020] 🔴 TAINTED write
├── [L15297] if (a2) ++a2[1021]  → a2[1021] 🔴 TAINTED write
├── [L15300] if (a2) a2[1017] += a4  → a2[1017] 🔴 TAINTED write (合并a4)
├── [L15306] if (a2) ++a2[1013]  → a2[1013] 🔴 TAINTED write
├── [L15309] if (a2) ++a2[1012]  → a2[1012] 🔴 TAINTED write
└── [L15312] if (a2) ++a2[1014]  → a2[1014] 🔴 TAINTED write
```

### INPUT-2: a3 (unsigned int) 🔴 TAINTED
```
a3 🔴 TAINTED
└── [L15270–L15319] 条件判断（14 处 if/else-if/switch 比较）
    ├── `a3 == 16` → L15271–L15272: `++a2[1011]`, `++result[57]`（常量下标）
    ├── `a3 <= 0x10` → L15274–L15293: 分支内使用编译期常量下标
    │   ├── `a3 == 12` → L15275–L15276: `++a2[1007]`, `++result[53]`
    │   ├── `a3 <= 0xC` → L15278–L15283: 下标 1005/1006/1008
    │   ├── `a3 == 14` → L15286–L15287: `++a2[1009]`, `++result[55]`
    │   └── `a3 > 0xE` → L15289–L15290: `++a2[1010]`, `++result[56]`
    ├── `a3 == 21` → L15296–L15297: `a2[1016] += a4`, `result[62] += a4`
    ├── `a3 > 0x15` → L15300–L15311: switch(0x16/0x19/0x1A)，常量下标
    ├── `a3 == 18` → L15314–L15315: `++a2[1013]`, `++result[59]`
    ├── `a3 < 0x12` → L15317–L15318: `++a2[1012]`, `++result[58]`
    └── `a3 == 19` → L15320–L15321: `++a2[1014]`, `++result[60]`
        └── [L15323] `return result` — result 本身非 a3，a3 未写入返回值

⚠️ 注：所有数组下标均为编译期常量，a3 仅决定进入哪个分支，不直接参与下标计算
```

### INPUT-3: a4 (int) 🔴 TAINTED
```
a4 🔴 TAINTED
├── [L15297] a3 == 21 时
│   ├── `a2[1016] += a4` → a2[1016] 🔴 TAINTED
│   └── `result[62] += a4` → result[62] 🔴 TAINTED
└── [L15307] a3 == 0x16 时
    ├── `a2[1017] += a4` → a2[1017] 🔴 TAINTED
    └── `result[63] += a4` → result[63] 🔴 TAINTED
```

## 新导入的污点对象（函数内部产生）

| 污点对象 | 类型 | 产生位置 | 来源 | 说明 |
|---------|------|---------|------|------|
| a2[1016] | uint32_t | L15289 | `a2[1016] += a4` | a4 累加到 a2 数组 |
| a2[1017] | uint32_t | L15300 | `a2[1017] += a4` | a4 累加到 a2 数组 |
| result[62] | uint32_t | L15289 | `result[62] += a4` | a4 累加到 result 数组 |
| result[63] | uint32_t | L15300 | `result[63] += a4` | a4 累加到 result 数组 |

## 污点终点汇总

| 脏数据 | 终点类型 | 位置 | 说明 |
|--------|----------|------|------|
| a2 | WRITE | L15269-L15312 | 14处写入统计数组 (常量下标) |
| a3 | CONDITIONAL | L15270-L15319 | 14处条件分支判断 |
| a4 | WRITE | L15289, L15300 | 累加到 a2[1016/1017] 和 result[62/63] |

## 接收此污点的子函数

| 文件 | 函数 | 调用行 | 接收的形参 |
|------|------|--------|----------|
| (无) | - | - | 本函数内无任何子函数调用，所有操作均为内联语句 |

## DIRECT_SINK 标记

无 DIRECT_SINK 风险 — a3 仅用于条件分支判断，所有数组下标均为编译期常量

---

## [46/61] IPSEC_NvsPrintfStrSetter  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `out_str` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_NvsPrintfStrSetter

## 函数信息
- 文件: libipsec.c
- 签名: `IPSEC_NvsPrintfStrSetter(uint8_t* out_str, const char* format, size_t max_len)`

## 数据流树状图

### INPUT-1: out_str (uint8_t*) 🔴 TAINTED
├── [L7735] vsnprintf_truncated_s(out_str, (unsigned int)(max_len + 1), format, ap) → 📌 USED (格式化输出写入 out_str 缓冲区)
│   └── 接收形参: out_str
└── [L7741] *out_str = 0 → 📌 USED (错误处理时写入单字节空字符)

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| out_str | USED | L7735 | 调用 vsnprintf_truncated_s 将数据格式化输出到缓冲区 |
| out_str | USED | L7741 | 错误处理路径写入空字符终止符 |

---

## [47/61] IPSEC_SADB_UpdatePktLenStats  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `a2` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `a3` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SADB_UpdatePktLenStats

## 函数信息
- 文件: libipsec.c
- 签名: `IPSEC_SADB_UpdatePktLenStats(int64_t result, int64_t a2, int a3)`

## 污点源

### INPUT-1: result (int64_t) 🔴 TAINTED
外部输入参数，作为 stats 结构体指针使用

### INPUT-2: a2 (int64_t) 🔴 TAINTED
外部输入参数，作为 stats 结构体指针使用

### INPUT-3: a3 (int) 🔴 TAINTED
外部输入参数，用于条件判断控制流

---

## 数据流树状图

### INPUT-1: result (int64_t) 🔴 TAINTED
```
result (int64_t) 🔴 TAINTED
│
└──[L15368] if (result) ++RAW_U32((void *)result, 256)
    └── ⚠️ DIRECT_SINK: 污染指针 result 用于内存解引用，偏移量 256 为常量
        └── 条件判断 result 非空 → 仅检查指针有效性，不影响数据流

result (int64_t) 🔴 TAINTED
│
└──[L15372] if (result) ++RAW_U32((void *)result, 272)
    └── ⚠️ DIRECT_SINK: 污染指针 result 用于内存解引用，偏移量 272 为常量
```

### INPUT-2: a2 (int64_t) 🔴 TAINTED
```
a2 (int64_t) 🔴 TAINTED
│
└──[L15367] if (a2) ++RAW_U32((void *)a2, 4072)
    └── ⚠️ DIRECT_SINK: 污染指针 a2 用于内存解引用，偏移量 4072 为常量

a2 (int64_t) 🔴 TAINTED
│
└──[L15371] if (a2) ++RAW_U32((void *)a2, 4088)
    └── ⚠️ DIRECT_SINK: 污染指针 a2 用于内存解引用，偏移量 4088 为常量
```

### INPUT-3: a3 (int) 🔴 TAINTED
```
a3 (int) 🔴 TAINTED
│
└──[L15366] if (a3 == 23) → 仅用于条件判断，无数据传播
│   ├── [L15367] if (a2) ++RAW_U32((void *)a2, 4072); → 无 a3 参与
│   └── [L15368] if (result) ++RAW_U32((void *)result, 256); → 无 a3 参与
├── [L15370] else if (a3 == 27) → 仅用于条件判断，无数据传播
│   ├── [L15371] if (a2) ++RAW_U32((void *)a2, 4088); → 无 a3 参与
│   └── [L15372] if (result) ++RAW_U32((void *)result, 272); → 无 a3 参与
└── [L15374] return result → 返回值与 a3 完全独立
    └── 🟢 a3 终止于 L15366/L15370，仅作为等值比较的控制流键值，无数据传播
```

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| result | ⚠️ DIRECT_SINK | L15368 | 污染指针 result 用于内存解引用，偏移量 256 为常量 |
| result | ⚠️ DIRECT_SINK | L15372 | 污染指针 result 用于内存解引用，偏移量 272 为常量 |
| a2 | ⚠️ DIRECT_SINK | L15367 | 污染指针 a2 用于内存解引用，偏移量 4072 为常量 |
| a2 | ⚠️ DIRECT_SINK | L15371 | 污染指针 a2 用于内存解引用，偏移量 4088 为常量 |
| a3 | 🟢 终止 | L15366/L15370 | 仅作为等值比较的控制流键值，无数据传播 |

---

## 新导入的污点对象
无 — 本函数未通过 `Recv/Read/Get` 等调用导入新对象

---

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| (无) | — | — |

---

## 安全评估
- result: 偏移量 256、272 为硬编码常量，未从 result 派生
- a2: 偏移量 4072、4088 为硬编码常量，未从 a2 派生
- result 和 a2 仅被检查非空后作为内存基址解引用，无边界检查
- 若 result 或 a2 指向攻击者可控的内存区域，可导致内存覆写
- a3: 仅用于控制流条件判断，无数据传播

---

## [48/61] IPSEC_ESP_HandleInputPktV4  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `lib_ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `packet_info` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `stats_ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_ESP_HandleInputPktV4

## 函数信息
- 文件: libipsec.c
- 签名: `void IPSEC_ESP_HandleInputPktV4(void *mbuf, unsigned int *packet_info, int64_t lib_ctx, int64_t stats_ctx)`

---

## 污点源 (4个)

| ID | 变量 | 类型 | 来源 | 说明 |
|----|------|------|------|------|
| INPUT-1 | mbuf | void* | 外部网络输入 | 承载 ESP 加密数据包 |
| INPUT-2 | packet_info | unsigned int* | 外部网络输入 | 包信息数组指针，来自解析输出 |
| INPUT-3 | lib_ctx | int64_t | 外部上下文句柄 | 安全库上下文 |
| INPUT-4 | stats_ctx | int64_t | 外部输入参数 | 统计上下文句柄 |

---

## 新导入的污点载体 (由输出参数/读取操作产生)

| 变量 | 类型 | 产生位置 | 来源 | 说明 |
|------|------|---------|------|------|
| ip_header | uint8_t* | L9821, L9829 | MBUF_MakeMemoryContinuous_fl | 从 mbuf 提取 IP 头 |
| esp_header | uint32_t* | L9830, L9842 | MBUF_MakeMemoryContinuous_fl | 从 mbuf 提取 ESP 头 |
| sa_lookup_key | uint32_t | L9859 | esp_header 字节序转换 | 用于 SA 查找 |
| dbg_flow_id | uint32_t | L9840 | packet_info[13] | 调试流 ID |
| authenticated_len | uint32_t | L1084 | packet_info[6] | 认证数据长度 |
| chunk_offset | uint32_t | L1097 | *packet_info | 分块偏移量 |
| received_auth | uint8_t[64] | L1082, L1093 | MBUF_CopyDataFromMBufToBuffer | mbuf 认证数据拷贝 |
| chunk | void* | L1095, L1104 | MBUF_MakeMemoryContinuous_fl | 加密有效载荷分块 |
| esp_tail_block | uint8_t[16] | L1159, L1161 | MBUF_CopyDataFromMBufToBuffer | ESP 尾部数据 |
| pad_length | uint8_t | L1191, L1194 | esp_tail_block[pad_index] | ESP 填充长度 |
| next_protocol | uint8_t | L1192, L1195 | esp_tail_block[pad_index+1] | 下一层协议 |

---

## 完整数据流树状图

### INPUT-1: mbuf (void*) 🔴 TAINTED
```
├── [L9821] MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...) → ip_header 🔴 TAINTED
│   └── [L9834] ip_header_words = ip_header[0] & 0xF → 边界控制
├── [L9829] MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...) → ip_header 🔴 TAINTED
├── [L9830] MBUF_MakeMemoryContinuous_fl(mbuf, *packet_info, 24, ...) → esp_header 🔴 TAINTED
│   └── [L9859] sa_lookup_key = __builtin_bswap32(*esp_header) → sa_lookup_key 🔴 TAINTED
│       └── [L9879] VOS_AVL3_Find(lib_ctx+120, &sa_lookup_key, ...) → 📎 子函数
├── [L9842] MBUF_MakeMemoryContinuous_fl(mbuf, *packet_info, 24, ...) → esp_header 🔴 TAINTED
│   └── [L9875] IPSEC_LIB_Ipv4AddrToStr(RAW_U32(ip_header,12), ...) → 调试输出
├── [L1082] MBUF_CopyDataFromMBufToBuffer(mbuf, packet_len-auth_hash_len, auth_hash_len, received_auth) → received_auth 🔴 TAINTED
├── [L1093] MBUF_CopyDataFromMBufToBuffer(mbuf, packet_len-auth_hash_len, auth_hash_len, received_auth) → received_auth 🔴 TAINTED
├── [L1095] MBUF_MakeMemoryContinuous_fl(mbuf, chunk_offset, chunk_len, ...) → chunk 🔴 TAINTED
├── [L1104] MBUF_MakeMemoryContinuous_fl(mbuf, chunk_offset, chunk_len, ...) → chunk 🔴 TAINTED
│   └── [L1113] AUTH_UPDATE(auth_desc, ..., chunk, chunk_len) → 🟡 EXPORT (标准加密库)
├── [L1153] MBUF_MakeMemoryContinuous_fl(mbuf, chunk_offset, enc_block_size, ...) → esp_tail_block 🔴 TAINTED
├── [L1159] MBUF_CopyDataFromMBufToBuffer(..., packet_len-enc_block_size-auth_hash_len, enc_block_size, esp_tail_block) → esp_tail_block 🔴 TAINTED
├── [L1161] MBUF_CopyDataFromMBufToBuffer(..., packet_len-enc_block_size-auth_hash_len, enc_block_size, esp_tail_block) → esp_tail_block 🔴 TAINTED
│   └── [L1168] IPSEC_ESP_Decryption(lib_ctx, mbuf, packet_info, ...) → 📎 子函数 (mbuf 进入解密)
├── [L1168] IPSEC_ESP_Decryption(lib_ctx, mbuf, packet_info, ...) → 📎 子函数
├── [L1237] MBUF_CheckSum(mbuf, ...) → 校验和计算 ⚠️ DIRECT_SINK
├── [L1245] MBUF_CutTail_fl(mbuf, pad_length+2+auth_hash_len, ...) → ⚠️ DIRECT_SINK: 截断大小受污点控制
│   └── [L1252] MBUF_CutPart_fl(mbuf, *packet_info, ...) → 📎 子函数
│       ├── [L1273] MBUF_CreateControlInfo_fl(mbuf, 10, 8, ...) → 📎 子函数
│       ├── [L1282] MBUF_SetFlag(mbuf, 0x10000000) → 📎 子函数
│       └── [L1284] MBUF_GetControlInfo(mbuf, 10) → 📎 子函数
└── [L1282] MBUF_SetFlag(mbuf, 0x10000000) → mbuf 标志设置
```

### INPUT-2: packet_info (unsigned int*) 🔴 TAINTED
```
├── [L9810] packet_info == NULL 验证检查 → 终止
├── [L9821] MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...) → ip_header 🔴 TAINTED
├── [L9830] MBUF_MakeMemoryContinuous_fl(mbuf, *packet_info, 24, ...) → esp_header 🔴 TAINTED
├── [L9840] dbg_flow_id = __builtin_bswap32(packet_info[13]) → dbg_flow_id 🔴 TAINTED
├── [L1028] packet_info[14] → RAW_U32(&algo_dbg_word, 0)
│   └── [L1030] IPSECL_DBG_EspPktAlgoV4(..., dbg_flow_id, ...) → 📎 子函数
├── [L1046] packet_len = packet_info[4] → packet_len 🔴 TAINTED
├── [L1048] *packet_info (offset) 用于 payload 长度验证
├── [L1053] packet_info[5] = payload_len → 写入
├── [L1056] packet_info[6] = SA_tail_size + 8 + payload_len → 写入
├── [L1084] authenticated_len = packet_info[6] → authenticated_len 🔴 TAINTED
├── [L1093] MBUF_CopyDataFromMBufToBuffer(..., packet_len-auth_hash_len, ...) → received_auth[] 🔴 TAINTED
├── [L1097] chunk_offset = *packet_info → chunk_offset 🔴 TAINTED
├── [L1104] MBUF_MakeMemoryContinuous_fl(mbuf, chunk_offset, chunk_len, ...) → chunk 🔴 TAINTED
│   └── [L1113] AUTH_UPDATE(auth_desc, ..., chunk, chunk_len) → 📎 子函数
├── [L1159] MBUF_CopyDataFromMBufToBuffer(..., packet_len-enc_block_size-auth_hash_len, ...) → esp_tail_block[] 🔴 TAINTED
├── [L1166] IPSEC_ESP_Decryption(lib_ctx, mbuf, packet_info, ...) → 📎 子函数 (packet_info 作为输出参数)
├── [L1193] pad_index = enc_block_size - 2
│   └── [L1194] pad_length = esp_tail_block[pad_index] → pad_length 🔴 TAINTED
│       └── [L1195] next_protocol = esp_tail_block[pad_index+1] → next_protocol 🔴 TAINTED
├── [L1196] *((uint8_t*)packet_info+29) = pad_length → 写入（来自 tainted esp_tail_block）
├── [L1197] *((uint8_t*)packet_info+32) = next_protocol → 写入（来自 tainted next_protocol）
├── [L1199] *packet_info 用于尾部长度边界验证
├── [L1216] ⚠️ DIRECT_SINK: ip_header[packet_info[1]] = esp_tail_block[pad_index+1] → packet_info[1] 作为数组下标
├── [L1218] ⚠️ DIRECT_SINK: ip_header[packet_info[1]] = next_protocol → 同上
├── [L1220] ip_header[9] = next_protocol → 🟢 CLEANED（固定索引9，非packet_info[1]）
├── [L1225] *((uint16_t*)packet_info+5) 用于 total_len 计算
├── [L1237] MBUF_CutTail_fl(mbuf, pad_length+2+auth_hash_len, ...) → pad_length 🔴 TAINTED
└── [L1248] MBUF_CutPart_fl(mbuf, *packet_info, ...) → *packet_info 🔴 TAINTED
```

### INPUT-3: lib_ctx (int64_t) 🔴 TAINTED
```
├── [L9810] lib_ctx == 0 验证检查 → 终止
├── [L9820] MBUF_MakeMemoryContinuous_fl(..., RAW_U64(lib_ctx,16), ...) → 📎 子函数
│   └── [L9841] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L9863] MBUF_MakeMemoryContinuous_fl(..., RAW_U64(lib_ctx,16), ...) → 📎 子函数
│   └── [L9870] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L9873] dbg_mode = RAW_U8(lib_ctx,400) → 控制流分支
│   └── [L9875] IPSEC_LIB_Ipv4AddrToStr(..., (int64_t)lib_ctx) → 📎 子函数
│   └── [L9876] IPSEC_LIB_Ipv4AddrToStr(..., (int64_t)lib_ctx) → 📎 子函数
├── [L1003] VOS_AVL3_Find(lib_ctx+120, ...) → 📎 子函数
│   └── [L1003] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1021] VOS_AVL3_Find(lib_ctx+76, ...) → 📎 子函数
│   └── [L1025-1027] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1035] IPSECL_DBG_EspPktAlgoV4(lib_ctx, ...) → 📎 子函数
├── [L1053] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1069] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1085] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1103] MBUF_MakeMemoryContinuous_fl(..., RAW_U64(lib_ctx,16), ...) → 📎 子函数
│   └── [L1110] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1115] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L1118] SSP_Debug(RAW_U32(lib_ctx,408), ..., RAW_U64(lib_ctx,440), ..., lib_ctx+448) → ⚠️ DIRECT_SINK: lib_ctx用作内存基址(偏移408,440,448)
├── [L1123] AUTH_FINAL(auth_desc, computed_auth, ..., lib_ctx, 64) → 📎 子函数
├── [L1127] RAW_U8(lib_ctx,403) → 控制流分支
│   └── [L1129] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
├── [L1130] IPSEC_PKT_DebugPacketV4(lib_ctx, ...) → 📎 子函数
├── [L1136] AUTH_FINAL(auth_desc, computed_auth, ..., lib_ctx, 64) → 📎 子函数
├── [L1139] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L1140] AUTH_FINAL(auth_desc, computed_auth, ..., lib_ctx, 64) → 📎 子函数
├── [L1145] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1146] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L1148] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
├── [L1155] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1157] IPSEC_ESP_Decryption(lib_ctx, ...) → 📎 子函数
├── [L1167] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1169] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L1171] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
├── [L1173] RAW_U8(lib_ctx,403) → 控制流分支
│   └── [L1174] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
├── [L1178] IPSEC_PKT_DebugPacketV4(lib_ctx, ...) → 📎 子函数
├── [L1185] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1195] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1204] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L1205] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1213] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L1215] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
├── [L1218] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
├── [L1234] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1241] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1248] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1261] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1263] MBUF_CreateControlInfo_fl(..., RAW_U64(lib_ctx,16), ...) → 📎 子函数
├── [L1269] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 📎 子函数
├── [L1285] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L1288] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
├── [L1290] IPSEC_PKT_DebugPacketV4(lib_ctx, ...) → 📎 子函数
└── [L1291] SSP_Debug(..., (const char*)(lib_ctx+448)) → ⚠️ DIRECT_SINK
```

### INPUT-4: stats_ctx (int64_t) 🔴 TAINTED
```
├── [L9789] if (... stats_ctx == 0) → 🟢 CLEANED（空指针检查，不参与数据处理）
├── [L9846] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, 0, 28, 0) → 📎 子函数
├── [L9924] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 4, 0) → 📎 子函数
├── [L10035] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 6, 0) → 📎 子函数
├── [L10047] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 8, 0) → 📎 子函数
├── [L10061] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10113] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10133] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10147] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10159] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10174] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 8, 0) → 📎 子函数
├── [L10186] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 8, 0) → 📎 子函数
├── [L10207] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 8, 0) → 📎 子函数
├── [L10238] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 6, 0) → 📎 子函数
├── [L10251] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 6, 0) → 📎 子函数
├── [L10257] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 24, 0) → 📎 子函数
├── [L10263] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10276] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10290] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
├── [L10303] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 21, ...) → 📎 子函数
└── [L10315] IPSEC_SADB_UpdateSaStatsV4(stats_ctx, sadb_entry, 28, 0) → 📎 子函数
```

---

## 关键 DIRECT_SINK 汇总

| 位置 | 危险操作 | 说明 |
|------|---------|------|
| L1118 | SSP_Debug(RAW_U32(lib_ctx,408), ..., RAW_U64(lib_ctx,440), ..., lib_ctx+448) | lib_ctx 作为内存基址，攻击者可控制调试输出；若被污染，可读取任意地址+448 |
| L1129, L1148, L1171, L1174, L1215, L1218, L1288, L1291 | SSP_Debug(..., (const char*)(lib_ctx+448)) | lib_ctx+448 作为字符串指针，可导致任意地址读取 |
| L1216 | ip_header[packet_info[1]] = esp_tail_block[pad_index+1] | packet_info[1] 作为数组下标受污点影响，可越界写入 IP 头 |
| L1218 | ip_header[packet_info[1]] = next_protocol | 同上 |
| L1222 | new_total_len = (uint16_t)(...) | pad_length 参与 uint32→uint16 截断，可能丢失高字节 |
| L1237 | MBUF_CheckSum(mbuf, ...) | mbuf 用于校验和计算 |
| L1245 | MBUF_CutTail_fl(mbuf, pad_length+2+auth_hash_len, ...) | mbuf 截断大小由污点 pad_length 决定 |
| L1196 | *((uint8_t*)packet_info+29) = pad_length | 将污点数据写入输出参数 packet_info |
| L1197 | *((uint8_t*)packet_info+32) = next_protocol | 将污点数据写入输出参数 packet_info |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf | 📎 子函数 | 多处 | 作为包缓冲区传递给多个 MBUF 函数处理 |
| packet_info | 📎 子函数 | 多处 | 作为包信息参数传递给解密和调试函数 |
| lib_ctx | ⚠️ DIRECT_SINK | L1118, L1129, L1148, L1171, L1174, L1215, L1218, L1288, L1291 | 作为内存基址用于调试输出 |
| stats_ctx | 📎 子函数 | 21处 | 作为句柄传递给统计更新函数 |
| ip_header | ⚠️ DIRECT_SINK | L1216, L1218 | 作为污点下标写入目标 |
| pad_length | ⚠️ DIRECT_SINK | L1245 | 作为截断长度参数 |
| esp_tail_block | *((uint8_t*)packet_info+...) | L1196, L1197 | 数据写入输出参数 |

---

## [49/61] IPSECL_DBG_AhPktAlgo  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `selector_words` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `algo_dbg_word` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSECL_DBG_AhPktAlgo

## 函数信息
- 文件: libipsec.c
- 函数签名:
```c
int64_t IPSECL_DBG_AhPktAlgo(
    int64_t lib_ctx,
    unsigned short **sa_type_desc,
    int64_t sadb_entry,
    int64_t selector1,
    int64_t selector2,
    unsigned int *packet_meta)
```

## 污点源
| 编号 | 参数 | 类型 | 状态 |
|------|------|------|------|
| INPUT-1 | selector1 | int64_t | 🔴 TAINTED |
| INPUT-2 | selector2 | int64_t | 🔴 TAINTED |
| INPUT-3 | packet_meta | unsigned int* | 🔴 TAINTED — 外部网络输入参数 |

## 新导入的污点对象
| 变量 | 类型 | 来源 | 行号 |
|------|------|------|------|
| dbg_mode | unsigned int | `*((uint8_t *)packet_meta + 4)` | L7865 |
| dbg_tag | unsigned int | `*packet_meta` | L7866 |

## 传播路径

### INPUT-1: selector1 (int64_t) 🔴 TAINTED
```
selector1 🔴 TAINTED
├── [L7872] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7878] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7900] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7905] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7915] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7921] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
└── [L7948] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
```

### INPUT-2: selector2 (int64_t) 🔴 TAINTED
```
selector2 🔴 TAINTED
├── [L7872] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7878] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7900] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7905] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7915] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
├── [L7921] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
└── [L7948] IPSEC_PKT_DebugPacket(..., selector1, selector2, ...) → 📎 SubFunction
```

### INPUT-3: packet_meta (unsigned int*) 🔴 TAINTED
```
packet_meta 🔴 TAINTED
├── [L7865] dbg_mode = *((uint8_t *)packet_meta + 4) → dbg_mode 🔴 TAINTED (新对象)
│   └── [L7873] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
│   └── [L7878] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
│   └── [L7900] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
│   └── [L7905] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
│   └── [L7915] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
│   └── [L7921] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
│   └── [L7940] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
│   └── [L7948] IPSEC_PKT_DebugPacket(..., dbg_mode, dbg_tag) → 📎 SubFunction
└── [L7866] dbg_tag = *packet_meta → dbg_tag 🔴 TAINTED (新对象)
    └── (同上, 8次调用传递 dbg_tag 作为参数)
```

## 接收此污点的子函数汇总

| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| IPSEC_PKT_DebugPacket | L7872, L7878, L7900, L7905, L7915, L7921, L7948 | selector1, selector2 |
| IPSEC_PKT_DebugPacket | L7873, L7878, L7900, L7905, L7915, L7921, L7940, L7948 | dbg_mode, dbg_tag |

## 安全备注

- 函数 `IPSECL_DBG_AhPktAlgo` 作为**调度器**角色，根据 `sa_type` 和 `dbg_mode` 条件将污点数据路由到 `IPSEC_PKT_DebugPacket` 的多个调用点
- 本函数体内，污点参数仅作为函数参数传递，未进行指针运算、数组索引或内存操作
- 新导入的污点对象 `dbg_mode` 和 `dbg_tag` 均源自 `packet_meta` 的直接解引用
- 未发现 DIRECT_SINK 模式（无 memcpy、整数截断、越界索引等）

---

## [50/61] IPSEC_AH_HandleInputPktV4  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `lib_ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `packet_info` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `stats_ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_AH_HandleInputPktV4

## 函数信息
- 文件: libipsec.c
- 签名: `int IPSEC_AH_HandleInputPktV4(void *lib_ctx_base, void *stats_ctx_base, void *mbuf, unsigned int *packet_info)`
- 外部输入参数:
  - `lib_ctx_base` — IPsec库上下文句柄
  - `stats_ctx_base` — IPsec SA统计上下文指针
  - `mbuf` — 网络数据包
  - `packet_info` — 数据包元信息数组

---

## 污点源汇总

| ID | 变量 | 类型 | 说明 |
|----|------|------|------|
| INPUT-1 | `lib_ctx_base` | int64_t | IPsec库上下文句柄，外部输入 |
| INPUT-2 | `stats_ctx_base` | int64_t | IPsec SA统计上下文指针，外部输入 |
| INPUT-3 | `mbuf` | void* | 网络数据包，来自IPv4入站流量 |
| INPUT-4 | `packet_info` | unsigned int* | 数据包元信息数组，外部网络输入 |

---

## 传播路径

### INPUT-1: lib_ctx_base (int64_t) 🔴 TAINTED
```
├── [L6718] NULL检查 → 干净
├── [L6724] MBUF_MakeMemoryContinuous_fl(..., RAW_U64(lib_ctx,16), ...) → mem_ops 🔴 TAINTED
├── [L6737] MBUF_MakeMemoryContinuous_fl(..., RAW_U64(lib_ctx,16), ...) → mem_ops 🔴 TAINTED
├── [L6760] if(RAW_U8(lib_ctx,400)==1||RAW_U8(lib_ctx,403)==1) → debug_flag 🔴 TAINTED (条件判断)
├── [L6770] VOS_AVL3_Find(lib_ctx+120, &sa_key, lib_ctx+144) → 📎 子函数
├── [L6791] VOS_AVL3_Find(lib_ctx+76, ..., lib_ctx+100) → 📎 子函数
├── [L6823] VRP_Malloc_F(RAW_U64(lib_ctx,8), ...) → mem_pool 🔴 TAINTED
│   └── 分配 header_copy → [L6850] MBUF_CopyDataFromMBufToBuffer → USED
├── [L6827-6846] SSP_Debug(..., (char*)(lib_ctx+448)) → 📎 子函数 (调试字符串)
├── [L6828-6847] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L6936] VRP_Malloc_F(RAW_U64(lib_ctx,8), ...) → mem_pool 🔴 TAINTED
│   └── 分配 payload_copy → [L7003] memcpy_s(payload_copy, ...) → USED
├── [L6943-6964] SSP_Debug(..., (char*)(lib_ctx+448)) → 📎 子函数
├── [L6944-6965] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L6983] MBUF_MakeMemoryContinuous_fl(..., RAW_U64(lib_ctx,16), ...) → mem_ops 🔴 TAINTED
├── [L6990] IPSEC_LIB_LOG_IF_ENABLED(lib_ctx, ...) → 日志 (不传递)
├── [L7019-7054] SSP_Debug(..., (char*)(lib_ctx+448)) → 📎 子函数
├── [L7020-7055] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
├── [L7057] algo_desc[9](computed_auth, auth_ctx, lib_ctx, 64) → 📎 子函数 (认证计算)
├── [L7066] algo_desc[9](computed_auth, auth_ctx, lib_ctx, 64) → 📎 子函数
├── [L7070] IPSEC_PKT_DebugPacketV4(lib_ctx, sadb_entry, ...) → 📎 子函数
├── [L7085] IPSEC_PKT_DebugPacketV4(lib_ctx, sadb_entry, ...) → 📎 子函数
├── [L7086-7088] SSP_Debug(..., (char*)(lib_ctx+448)) → 📎 子函数
├── [L7087] IPSEC_MakeDbgLibStrSetter(lib_ctx, ...) → 📎 子函数
└── [L7102] MBUF_CreateControlInfo_fl(mbuf, 10, 8, RAW_U64(lib_ctx,16), ...) → ⚠️ DIRECT_SINK
```

#### 派生: mem_pool 🔴 TAINTED
- [L6823,L6936] VRP_Malloc_F(mem_pool, ...) → 分配包数据缓冲区

#### 派生: mem_ops 🔴 TAINTED
- [L6724,L6737,L6983] MBUF_MakeMemoryContinuous_fl(..., mem_ops, ...) → 内存连续化
- [L7102] MBUF_CreateControlInfo_fl(..., mem_ops, ...) → ⚠️ DIRECT_SINK

---

### INPUT-2: stats_ctx_base (int64_t) 🔴 TAINTED
```
├── [L6743] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, 0, 28, 0) → 🟡 EXPORT (错误路径)
├── [L6759] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, 0, 28, 0) → 🟡 EXPORT (错误路径)
├── [L6784] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 5, 0) → 🟡 EXPORT (错误路径)
├── [L6798] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 5, 0) → 🟡 EXPORT (错误路径)
├── [L6805] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 24, 0) → 🟡 EXPORT (错误路径)
├── [L6819] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 6, 0) → 🟡 EXPORT (错误路径)
├── [L6873] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 28, 0) → 🟡 EXPORT (错误路径)
├── [L7082] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 8, 0) → 🟡 EXPORT (错误路径)
├── [L7096] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 28, 0) → 🟡 EXPORT (错误路径)
├── [L7105] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 28, 0) → 🟡 EXPORT (错误路径)
└── [L7111] IPSEC_SADB_UpdateSaStatsV4(stats_ctx_base, sadb_entry, 21, packet_info[6]) → 🟡 EXPORT
    └── ⚠️ DIRECT_SINK: packet_info[6] 写入统计上下文
```

---

### INPUT-3: mbuf (void*) 🔴 TAINTED
```
├── [L6734] ip_header = MBUF_MakeMemoryContinuous_fl(mbuf, 0, *packet_info, ...)
│   └── ip_header 🔴 TAINTED
│       ├── [L6754] ip_header_len = 4u * (RAW_U8(ip_header,0) & 0xF) → ip_header_len 🔴 TAINTED
│       │   └── [L6755] ah_header = (uint8_t*)(ip_header + ip_header_len)
│       │       ├── ⚠️ DIRECT_SINK: 指针运算，偏移量ip_header_len来自mbuf
│       │       ├── [L6805] 4u * ah_header[1] (uint8_t→uint32截断)
│       │       ├── [L6765] ah_spi_host = *(uint32_t*)(ah_header+4)
│       │       ├── [L6869] algo_desc[7](auth_ctx, header_copy, 20)
│       │       └── [L6927] algo_desc[7](auth_ctx, ah_header, 12)
│       └── [L6928] algo_desc[7](auth_ctx, &g_aucIpsecZeroes, auth_hash_len)
├── [L6746] MBUF_MakeMemoryContinuous_fl(mbuf, *packet_info, packet_info[4]-*packet_info, ...)
├── [L6820] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, *packet_info, header_copy)
│   └── header_copy 🔴 TAINTED
│       ├── [L6879-6904] 循环解析IP options: header_copy[offset], header_copy[offset+1] 🔴 TAINTED
│       └── ⚠️ DIRECT_SINK: option_offset/option_len来自mbuf数据
├── [L6973] read_offset = payload_offset (auth_hash_len+12+*packet_info) → read_offset 🔴 TAINTED
├── [L6977] chunk_base = MBUF_MakeMemoryContinuous_fl(mbuf, read_offset, chunk_len, ...)
│   └── chunk_base 🔴 TAINTED
│       ├── [L6987] memcpy_s(payload_copy, chunk_base, chunk_len)
│       │   └── ⚠️ DIRECT_SINK: 大小chunk_len和源指针chunk_base均来自mbuf
│       └── payload_copy 🔴 TAINTED
│           └── [L7027] algo_desc[7](auth_ctx, payload_copy, payload_len)
├── [L7038] VOS_MemCmp(computed_auth, ah_header+12, auth_hash_len) (认证校验)
├── [L7065] MBUF_CheckSum(mbuf, ip_header_len)
├── [L7067] MBUF_CutPart_fl(mbuf, *packet_info, auth_hash_len+12, ...)
├── [L7076] MBUF_CreateControlInfo_fl(mbuf, 10, 8, ...)
├── [L7090] MBUF_SetFlag(mbuf, 0x10000000)
└── [L7091] MBUF_GetControlInfo(mbuf, 10) 📌 USED
```

#### 派生: ip_header 🔴 TAINTED
- 从 mbuf 内部内存提取，受 packet_info 控制

#### 派生: ah_header 🔴 TAINTED
- 从 ip_header 偏移 ip_header_len 提取，受 mbuf 数据控制

#### 派生: header_copy 🔴 TAINTED
- MBUF_CopyDataFromMBufToBuffer 写入，接收 mbuf 数据

#### 派生: chunk_base 🔴 TAINTED
- MBUF_MakeMemoryContinuous_fl 从 mbuf 读取 payload 块

#### 派生: payload_copy 🔴 TAINTED
- memcpy_s 从 chunk_base 拷贝到 payload_copy，chunk_len 受 mbuf 数据控制

---

### INPUT-4: packet_info (unsigned int*) 🔴 TAINTED
```
├── packet_info[0] (*packet_info = IP头偏移/长度)
│   ├── [L6729] ip_offset = *packet_info → ip_offset 🔴 TAINTED
│   ├── [L6731] MBUF_MakeMemoryContinuous(mbuf, 0, *packet_info, ...) ⚠️ DIRECT_SINK
│   └── [L6823] MBUF_CopyDataFromMBufToBuffer(mbuf, 0, *packet_info, header_copy) ⚠️ DIRECT_SINK
├── packet_info[4] (数据包总长)
│   └── [L6737] MBUF_MakeMemoryContinuous(mbuf, *packet_info, packet_info[4]-*packet_info, ...) ⚠️ DIRECT_SINK
├── packet_info[5] (AH头总长)
│   ├── [L6803] VRP_Malloc_F(..., packet_info[5], ...) ⚠️ DIRECT_SINK
│   ├── [L6823] MBUF_CopyDataFromMBufToBuffer(..., *packet_info, ...) — 拷贝包含头部长度信息的数据
│   ├── [L6860] *(header_copy+2) = __builtin_bswap16(*((uint16_t *)packet_info+5)) ⚠️ DIRECT_SINK
│   └── [L6867] ip_header.total_length = packet_info[5] - auth_hash_len - 12 ⚠️ DIRECT_SINK
│       └── → packet_info[5] 污染IPv4 total_length协议头字段
├── packet_info[5] → NEW TAINTED CARRIER
│   └── [L6827] packet_info[5] = payload_len — 污点计算结果写入输出参数
├── packet_info[6] → NEW TAINTED CARRIER
│   ├── [L6828] packet_info[6] = payload_len — 污点计算结果写入输出参数
│   └── [L7134] IPSEC_SADB_UpdateSaStatsV4(..., packet_info[6]) → 🟡 EXPORT
├── packet_info[13] → debug_flow 🔴 TAINTED
│   └── [L6729] debug_flow = __builtin_bswap32(packet_info[13])
└── packet_info[14] → NEW TAINTED CARRIER
    ├── [L7057] IPSEC_PKT_DebugPacketV4(..., packet_info[14]) → 📎 见跟入列表
    ├── [L7069] IPSEC_PKT_DebugPacketV4(..., packet_info[14]) → 📎 见跟入列表
    ├── [L7122] IPSEC_PKT_DebugPacketV4(..., packet_info[14]) → 📎 见跟入列表
    └── [L7135] IPSEC_PKT_DebugPacketV4(..., packet_info[14]) → 📎 见跟入列表
```

#### 派生: packet_info[5] (NEW CARRIER) 🔴 TAINTED
- 由污点计算赋值写入输出参数，驱动后续分配、拷贝、协议头修改

#### 派生: packet_info[6] (NEW CARRIER) 🔴 TAINTED
- 由污点计算赋值写入输出参数，传入 IPSEC_SADB_UpdateSaStatsV4

#### 派生: packet_info[14] (NEW CARRIER) 🔴 TAINTED
- 由 packet_info 读取后作为调试标签参数传入子函数

---

## ⚠️ DIRECT_SINK 汇总

| 位置 | 危险操作 | 描述 |
|------|---------|------|
| L6731 | MBUF_MakeMemoryContinuous(..., *packet_info, ...) | *packet_info 控制内存区域长度，可能访问无效内存 |
| L6737 | MBUF_MakeMemoryContinuous(..., packet_info[4]-*packet_info, ...) | 长度受污点控制 |
| L6755 | ah_header = (uint8_t*)(ip_header + ip_header_len) | 指针运算，偏移量ip_header_len来自mbuf |
| L6803 | VRP_Malloc_F(..., packet_info[5], ...) | packet_info[5] 控制堆分配大小，可能堆溢出 |
| L6823 | MBUF_CopyDataFromMBufToBuffer(..., *packet_info, ...) | *packet_info 控制拷贝数据量 |
| L6860 | *(header_copy+2) = __builtin_bswap16(*((uint16_t *)packet_info+5)) | packet_info[5] 数据写入栈缓冲区 |
| L6867 | ip_header.total_length = packet_info[5] - auth_hash_len - 12 | packet_info[5] 修改网络协议头完整性 |
| L6879-6904 | 循环解析 IP options，offset/len 来自 mbuf | header_copy 内污点驱动循环越界 |
| L6977 | MBUF_MakeMemoryContinuous_fl(mbuf, read_offset, chunk_len, ...) | read_offset 和 chunk_len 受 mbuf 数据控制 |
| L6987 | memcpy_s(payload_copy, chunk_base, chunk_len) | chunk_len 大小和 chunk_base 指针均来自 mbuf |
| L7027 | algo_desc[7](auth_ctx, payload_copy, payload_len) | payload_copy 载体和 payload_len 均来自 mbuf 解析 |
| L7057等 | IPSEC_PKT_DebugPacketV4(..., packet_info[14]) | packet_info[14] 作为调试标签传入子函数 |
| L7102 | MBUF_CreateControlInfo_fl(mbuf, 10, 8, RAW_U64(lib_ctx,16), ...) | mem_ops 来自 lib_ctx 偏移16写入 mbuf |
| L7111 | IPSEC_SADB_UpdateSaStatsV4(..., packet_info[6]) | packet_info[6] 写入统计上下文 |
| L6805 | 4u * ah_header[1] (uint8_t→uint32截断) | AH payload length 计算，截断后用于内存操作 |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| lib_ctx_base | MBUF_CreateControlInfo_fl | L7102 | mem_ops 写入 mbuf 控制信息 |
| mbuf | header_copy | L6820 | MBUF_CopyDataFromMBufToBuffer 写入栈缓冲区 |
| packet_info[5] | VRP_Malloc_F | L6803 | 控制堆分配大小 |
| packet_info[5] | header_copy | L6860 | 数据写入栈缓冲区 |
| packet_info[5] | IPv4 total_length | L6867 | 污染网络协议头字段 |
| packet_info[6] | IPSEC_SADB_UpdateSaStatsV4 | L7134 | 污点数据写入统计上下文 |
| packet_info[14] | IPSEC_PKT_DebugPacketV4 | L7057/7069/7122/7135 | 污点数据作为调试标签参数 |
| mbuf | chunk_base/payload_copy | L6977/6987 | 从 mbuf 提取并拷贝 payload 数据 |
| *packet_info | MBUF_MakeMemoryContinuous | L6731 | IP头偏移作为内存区域长度参数 |
| packet_info[4] | MBUF_MakeMemoryContinuous | L6737 | 总长控制读取区域大小 |
| stats_ctx_base | IPSEC_SADB_UpdateSaStatsV4 | L6743-L7111 | 统计上下文各错误路径汇总 |

---

## [51/61] IPSEC_LIB_LOG_IF_ENABLED  ·  被跟入函数

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

---

## [52/61] IPSEC_SADB_UpdateSaStatsV4  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `stats_ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SADB_UpdateSaStatsV4

## 函数信息
- 文件: libipsec.c
- 签名: `int IPSEC_SADB_UpdateSaStatsV4(uint32_t *result, int a2, int a3, int a4)`

## 污点源
| 参数 | 类型 | 状态 | 说明 |
|------|------|------|------|
| result | uint32_t * | 🔴 TAINTED | 外部调用者传入的统计上下文指针 |

## 新导入的污点对象
无新对象导入 — 本函数无 Recv/Read/Decode/Parse 类调用

## 传播路径

### result 🔴 TAINTED
├── [L15601] def_2FD10(result, a2, a3, a4)
│   ├── [L15617] if (!result) return ... → 空指针检查
│   ├── [L15618] ++result[71] → stats 数组写入 (case 1)
│   ├── [L15628] IPSEC_SADB_UpdateAuthFailStatsV4(result, a2, a3)
│   │   → 📎 见子函数表 (cases 2,6,8)
│   ├── [L15644] if (!result) return ...
│   ├── [L15645] ++result[73] → (case 3)
│   ├── [L15649] if (!result) return ...
│   ├── [L15650] ++result[74] → (case 4)
│   ├── [L15654] if (!result) return ...
│   ├── [L15655] ++result[75] → (case 5)
│   ├── [L15659] if (!result) return ...
│   ├── [L15660] ++result[77] → (case 7)
│   ├── [L15664] if (!result) return ...
│   ├── [L15665] ++result[79] → (case 9)
│   ├── [L15674] IPSEC_SADB_UpdateInOutPktStatsV4(result, a2, a3, a4)
│   │   → 📎 见子函数表 (cases 0xA-0x16,0x19,0x1A)
│   ├── [L15679] if (!result) return ...
│   ├── [L15680] ++result[90] → (case 0x14)
│   ├── [L15684] IPSEC_SADB_UpdatePktLenStatsV4(result, a2, a3)
│   │   → 📎 见子函数表 (cases 0x17,0x1B)
│   ├── [L15688] if (!result) return ...
│   ├── [L15689] ++result[94] → (case 0x18)
│   ├── [L15691] sub_2FD14(result, a2)
│   │   → 📎 见子函数表 (case 0x1C)
│   ├── [L15697] if (!result) return ...
│   ├── [L15698] ++result[99] → (case 0x1D)
│   └── [L15703] return (int64_t)(uintptr_t)result
│       → 📌 透传指针作为返回值

## 接收此污点的子函数

| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| def_2FD10 | L15601 | result |
| IPSEC_SADB_UpdateAuthFailStatsV4 | L15628 | result |
| IPSEC_SADB_UpdateInOutPktStatsV4 | L15674 | result |
| IPSEC_SADB_UpdatePktLenStatsV4 | L15684 | result |
| sub_2FD14 | L15691 | result |

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| result | 数组写入 | L15618,15645,15650,15655,15660,15665,15680,15689,15698 | stats 计数器安全递增 |
| result | 透传返回 | L15703 | 指针作为返回值 |

## 安全备注
- 所有 `++result[常量索引]` 操作均为 stats 计数器安全递增，无越界风险
- 本函数为分发器，无 DIRECT_SINK 风险

---

## [53/61] IPSECL_DBG_EspPktAlgo  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `algo_dbg_word` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `selector_pair` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `selector_pair_hi` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSECL_DBG_EspPktAlgo

## 函数信息
- 文件: libipsec.c
- 签名: `int64_t IPSECL_DBG_EspPktAlgo(int64_t lib_ctx, unsigned short **sa_type_desc, int64_t sadb_entry, int64_t selector1, int64_t selector2, unsigned int *packet_meta)`
- 功能: ESP包算法调试信息打印，接收网络报文元数据和选择器对

---

## 合并污点源 (4个外部输入)

| 序号 | 参数 | 类型 | 来源 |
|------|------|------|------|
| INPUT-1 | packet_meta | unsigned int* | 调用者通过 `packet_info[14]` 填充网络报文元数据 |
| INPUT-2 | selector1 | int64_t | 外部输入参数（第4形参），从 `packet_info[]` 构造 |
| INPUT-3 | selector2 | int64_t | 外部输入参数（第5形参），从 `packet_info[]` 构造 |
| INPUT-4 | dbg_mode | uint8_t | 从 packet_meta+4 提取的污点值 |
| INPUT-5 | dbg_tag | uint32_t | 从 packet_meta+0 提取的污点值 |

---

## 新导入的污点对象

- **无新污点对象导入**：函数内部未调用 Recv/Read/Recvfrom 等导入外部数据的函数
- 所有污点均来源于函数形参

---

## 传播路径

### INPUT-1: packet_meta (unsigned int*) 🔴 TAINTED
```
packet_meta 🔴 TAINTED
├── [L7970] dbg_tag = *packet_meta → dbg_tag 🔴 TAINTED
└── [L7969] dbg_mode = *((uint8_t *)packet_meta + 4) → dbg_mode 🔴 TAINTED
```

### INPUT-2: selector1 (int64_t) 🔴 TAINTED
```
selector1 🔴 TAINTED (第4形参，外部输入)
```

### INPUT-3: selector2 (int64_t) 🔴 TAINTED
```
selector2 🔴 TAINTED (第5形参，外部输入)
```

---

## 污点汇聚: 所有4个污点参数透传给 IPSEC_PKT_DebugPacket

**所有10处调用均传递完整的4个污点参数：**
```
IPSEC_PKT_DebugPacket(lib_ctx, sadb_entry, selector1, selector2, dbg_mode, dbg_tag)
```

| 调用位置 | 分支上下文 | 传递的污点参数 |
|----------|------------|----------------|
| L7980 | sa_type == 3 首次调用 | selector1, selector2, dbg_mode, dbg_tag |
| L7985 | sa_type == 3 重试 | selector1, selector2, dbg_mode, dbg_tag |
| L8011 | sa_type == 5 分支 | selector1, selector2, dbg_mode, dbg_tag |
| L8016 | sa_type == 5 重试 | selector1, selector2, dbg_mode, dbg_tag |
| L8053 | 默认分支 dbg_mode==1 | selector1, selector2, dbg_mode, dbg_tag |
| L8059 | 默认分支 dbg_mode==2 | selector1, selector2, dbg_mode, dbg_tag |
| L8069 | after_type_log dbg_mode==1 | selector1, selector2, dbg_mode, dbg_tag |
| L8075 | after_type_log dbg_mode==2 | selector1, selector2, dbg_mode, dbg_tag |
| L8088 | auth_log dbg_mode==1 | selector1, selector2, dbg_mode, dbg_tag |
| L8096 | auth_log dbg_mode==2 | selector1, selector2, dbg_mode, dbg_tag |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| packet_meta | 📎 IPSEC_PKT_DebugPacket | L7980-L8096 (10处) | 网络报文元数据指针 |
| dbg_mode | 📎 IPSEC_PKT_DebugPacket | L7980-L8096 (10处) | 从 packet_meta+4 提取的 uint8 |
| dbg_tag | 📎 IPSEC_PKT_DebugPacket | L7980-L8096 (10处) | 从 packet_meta+0 提取的 uint32 |
| selector1 | 📎 IPSEC_PKT_DebugPacket | L7980-L8096 (10处) | ESP选择器低64位 |
| selector2 | 📎 IPSEC_PKT_DebugPacket | L7980-L8096 (10处) | ESP选择器高64位 |

---

## DIRECT_SINK 标注

- **无 DIRECT_SINK**：函数体内无 memcpy/strcpy/sprintf/数组下标等直接危险操作使用污点数据
- 所有污点数据均透传给外部导出函数 `IPSEC_PKT_DebugPacket` 作为调试参数

---

## 说明

1. **函数签名**：实际函数有6个参数：`lib_ctx, sa_type_desc, sadb_entry, selector1, selector2, packet_meta`
2. **污点汇聚**：所有4个污点值（selector1, selector2, dbg_mode, dbg_tag）在10处调用点全部透传给 `IPSEC_PKT_DebugPacket`
3. **外部导出函数**：`IPSEC_PKT_DebugPacket` 为外部导出函数，标记为 🟡 EXPORT

---

## [54/61] sub_2FD14  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `result` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: sub_2FD14

## 函数信息
- 文件: libipsec.c
- 行号: L15692-L15694
- 签名: `int64_t sub_2FD14(int64_t result)`

## 污点源
| 参数 | 类型 | 状态 | 说明 |
|------|------|------|------|
| result | int64_t | 🔴 TAINTED | 外部输入参数，调用者传入的指针 |

## 新导入的污点对象
无

## 传播路径

### INPUT-1: result (int64_t) 🔴 TAINTED
```
[L15692] if (result) → 条件判断，控制后续写操作是否执行
[L15693] ++RAW_U32((void *)result, 392) → ⚠️ DIRECT_SINK: 污点指针作为基址，
    写入偏移 392 字节处的 uint32 字段（整数增量写）
[L15694] return result → 📌 USED: 污点指针直接返回给调用者
```

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| result | ⚠️ DIRECT_SINK | L15693 | 污点指针作为基址，写入偏移 392 字节处的 uint32 字段 |
| result | 📌 USED | L15694 | 污点指针直接返回给调用者 |

---

## [55/61] IPSEC_SADB_UpdateInOutPktStatsV4  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `result` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SADB_UpdateInOutPktStatsV4

## 函数信息
- 文件: libipsec.c
- 行号: L15488-L15570
- 签名: `uint32_t* IPSEC_SADB_UpdateInOutPktStatsV4(int a3, int a4, uint32_t* result)`

## 数据流树状图

### INPUT-1: result (uint32_t*) 🔴 TAINTED
├── [L15493] if (result) ++result[86]; → result[86] 写硬编码索引
├── [L15495] if (a3 == 12) ++result[82]; → result[82] 写硬编码索引
├── [L15497] if (a3 == 10) ++result[80]; → result[80] 写硬编码索引
├── [L15499] if (a3 == 11) ++result[81]; → result[81] 写硬编码索引
├── [L15501] if (a3 == 14) ++result[84]; → result[84] 写硬编码索引
├── [L15503] if (a3 > 0xE) ++result[85]; → result[85] 写硬编码索引
├── [L15505] else ++result[83]; → result[83] 写硬编码索引
├── [L15521] if (a3 == 21) result[91] += a4; → result[91] 累加，索引硬编码
├── [L15527] case 0x19: ++result[95]; → result[95] 写硬编码索引
├── [L15529] case 0x1A: ++result[96]; → result[96] 写硬编码索引
├── [L15531] case 0x16: result[92] += a4; → result[92] 累加，索引硬编码
├── [L15542] if (a3 == 18) ++result[88]; → result[88] 写硬编码索引
├── [L15546] if (a3 < 0x12) ++result[87]; → result[87] 写硬编码索引
├── [L15550] if (a3 == 19) ++result[89]; → result[89] 写硬编码索引
└── [L15558] return result; → 📌 USED (返回输出缓冲区指针)

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| result | WRITE | L15493-L15550 | 输出缓冲区写入，硬编码索引，无污点数据参与计算 |
| result | RETURN | L15558 | 返回输出缓冲区指针给调用者 |

## 结论
`result` 是输出缓冲区指针，所有写入操作均使用硬编码数组索引，无污点数据参与索引计算，无安全风险。

---

## [56/61] IPSEC_SADB_UpdateAuthFailStatsV4  ·  被跟入函数

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

---

## [57/61] def_2FD10  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `result` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: def_2FD10

## 函数信息
- 文件: libipsec.c
- 行号: L15611-L15671
- 签名: `int64_t def_2FD10(void *result, int a2, int a3, int a4)`

## 数据流树状图

### INPUT-1: result (void*) 🔴 TAINTED
├── [L15611] if (!result) return result → null检查，不传播污点
├── [L15612] ++result[71] → 数组元素自增，值被消费
│
├── [L15614] return (int64_t)(uintptr_t)result → 返回指针给调用者
│
├── [L15616] IPSEC_SADB_UpdateAuthFailStatsV4(result, a2, a3)
│   └── 📎 CALLEE: 接收污点参数 result
│
├── [L15621] ++result[73] → 数组元素自增
├── [L15624] ++result[74] → 数组元素自增
├── [L15628] ++result[75] → 数组元素自增
├── [L15632] ++result[77] → 数组元素自增
├── [L15636] ++result[79] → 数组元素自增
│
├── [L15656] IPSEC_SADB_UpdateInOutPktStatsV4(result, a2, a3, a4)
│   └── 📎 CALLEE: 接收污点参数 result
│
├── [L15657] ++result[90] → 数组元素自增
├── [L15663] ++result[94] → 数组元素自增
│
├── [L15664] IPSEC_SADB_UpdatePktLenStatsV4(result, a2, a3)
│   └── 📎 CALLEE: 接收污点参数 result
│
├── [L15666] sub_2FD14(result, a2)
│   └── 📎 CALLEE: 接收污点参数 result
│
├── [L15669] ++result[99] → 数组元素自增
└── [L15671] return result → 返回指针给调用者

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| result | array_index | L15612,15621,15624,15628,15632,15636,15657,15663,15669 | 数组索引操作，值被消费 |
| result | return | L15614,15671 | 返回指针给调用者 |
| result | CALLEE | L15616,15656,15664,15666 | 污点指针传入子函数 |

## 新导入的污点对象

无新污点对象从外部导入。

---

## [58/61] IPSEC_SADB_UpdatePktLenStatsV4  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `result` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SADB_UpdatePktLenStatsV4

## 函数信息
- 文件: libipsec.c
- 函数签名: `int64_t IPSEC_SADB_UpdatePktLenStatsV4(int64_t result, int64_t a2, int a3)`
- 函数功能: 更新IPv4包长统计，通过将传入的整数值强制转换为指针并进行内存写操作

## 污点源

| 输入参数 | 类型 | 状态 | 说明 |
|---------|------|------|------|
| result | int64_t | 🔴 TAINTED | 外部调用者传入的整数，被强制转换为指针使用 |

## 新导入的污点对象

| 变量 | 类型 | 导入方式 | 说明 |
|------|------|----------|------|
| 无 | — | — | 此函数无 Recv/Read/Decode/Parse 等数据导入调用 |

## 传播路径树状图

```
### INPUT: result (int64_t) 🔴 TAINTED - 外部调用者传入的整数，被强制转换为指针使用
├── [L15585] if (result) ++RAW_U32((void*)result, 372)
│   ⚠️ DIRECT_SINK: result 强转为 (uint8_t*) 并加上固定偏移 372，dereference 为 uint32_t* 后自增
│   → 攻击者通过 result 控制写操作的目标地址（任意内存写）
├── [L15588] if (result) ++RAW_U32((void*)result, 388)
│   ⚠️ DIRECT_SINK: 同上，目标地址 = result + 388，攻击者完全可控
└── [L15590] return result
    📌 USED: 作为 int64_t 返回值
```

## 子函数跟入列表

| 文件 | 函数 | 调用行 | 接收的形参 | 状态 |
|------|------|--------|-----------|------|
| — | — | — | — | 无子函数调用（两处危险操作均为内联宏 RAW_U32） |

## 污点终点汇总

| 污点数据 | 终点类型 | 位置 | 说明 |
|---------|---------|------|------|
| result | ⚠️ DIRECT_SINK | L15585 | `++RAW_U32((void*)result, 372)` — 宏展开为 `(*(uint32_t*)((uint8_t*)(result)+372))`，result 作为指针基址，攻击者可写任意内存 |
| result | ⚠️ DIRECT_SINK | L15588 | `++RAW_U32((void*)result, 388)` — 同上，目标地址为 result+388 |
| result | 📌 USED | L15590 | `return result` |

## 安全分析

RAW_U32 宏定义为：`(*(uint32_t*)((uint8_t*)(base) + (off)))`，两处调用均使用 result 作为 base 进行指针运算并写入内存。`if (result)` 仅排除零值，无法阻止指向任意用户可控地址的指针。

---

## [59/61] AUTH_UPDATE  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `auth_desc` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `auth_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `chunk=tainted_mbuf_data` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `chunk_len` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: AUTH_UPDATE

## 函数信息
- 文件: libipsec.c
- 上下文: IPSEC_ESP_HandleInputPkt (IPv6/IPv4) 子函数
- 签名: `AUTH_UPDATE(auth_desc, auth_state, data_ptr, data_len)` (宏展开为 `*(auth_desc+28)(auth_state, data_ptr, data_len)`)

## 污点源 (输入参数)

### INPUT-1: auth_desc (uint32_t *) 🔴 TAINTED
- 来源: 从 SADB 加载，`RAW_U64((void*)sa_entry, 16)` 获取
- 用途: auth_desc+28 存放更新回调函数指针
```
├── [L9498] AUTH_INIT(auth_desc, ...) → *(auth_desc+44) 初始化函数
├── [L9534] AUTH_UPDATE(auth_desc, auth_state[0], chunk, chunk_len)
│   └── ⚠️ DIRECT_SINK: *(auth_desc+28)(auth_state, chunk, chunk_len) — 函数指针解引用
├── [L9575] AUTH_INIT(auth_desc, ...) → *(auth_desc+44)
├── [L9576] AUTH_UPDATE(auth_desc, auth_state[0], computed_auth, RAW_U16(auth_desc,14))
│   └── ⚠️ DIRECT_SINK: *(auth_desc+28)(auth_state, computed_auth, tainted_len)
│   └── ⚠️ RAW_U16(auth_desc,14) 长度字段从污点 auth_desc 读取
└── [L9577] AUTH_FINAL(auth_desc, computed_auth, ...) → *(auth_desc+36) 最终函数
```

### INPUT-2: auth_state (int64_t / uint64_t[2]) 🔴 TAINTED
- 来源: 栈局部变量，由 `AUTH_INIT` 从 SADB/SA_ENTRY 写入，值受网络包 SPI 字段控制
- 传播: `auth_state[0]` 派生成新的污点载体
```
├── [L9498] AUTH_INIT(auth_desc, (int64_t *)auth_state, ...) → auth_state[0] 🔴 TAINTED
├── [L9534] AUTH_UPDATE(auth_desc, (int64_t)auth_state[0], chunk, chunk_len)
│   └── ⚠️ DIRECT_SINK: *(auth_desc+28)(auth_state[0], chunk, chunk_len) — 第一参数受污点
├── [L9577] AUTH_FINAL(auth_desc, computed_auth, (int64_t)auth_state[0], ...)
│   └── ⚠️ DIRECT_SINK: *(auth_desc+36) 函数指针解引用，auth_state[0] 参与
└── [L9576] AUTH_UPDATE(auth_desc, (int64_t)auth_state[0], computed_auth, RAW_U16(desc,14))
    └── ⚠️ DIRECT_SINK: *(auth_desc+28)(auth_state[0], computed_auth, tainted_len)
```

### INPUT-3: data_ptr (chunk / computed_auth) 🔴 TAINTED
- 来源: mbuf 网络负载数据，由 `MBUF_MakeMemoryContinuous_fl` 从 ESP 包提取
- 传播: computed_auth 由 `AUTH_FINAL` 对 chunk 计算 HMAC 后产生
```
├── [L9523] chunk = MBUF_MakeMemoryContinuous_fl(mbuf, chunk_offset, chunk_len, ...) → chunk 🔴 TAINTED
├── [L9534] AUTH_UPDATE(auth_desc, auth_state, chunk, chunk_len)
│   └── ⚠️ DIRECT_SINK: chunk 作为 data_ptr 传入外部 HMAC_Update 风格回调
├── [L9576] AUTH_FINAL(auth_desc, computed_auth, ...) → computed_auth 🔴 TAINTED
│   └── computed_auth 是 chunk 数据的 HMAC 计算结果
└── [L9579] AUTH_UPDATE(auth_desc, auth_state, computed_auth, auth_hash_len)
    └── computed_auth (🔴 TAINTED) 作为 data_ptr 传入第二阶段外部认证回调
```

### INPUT-4: data_len (chunk_len / auth_hash_len) 🔴 TAINTED
- 来源: 网络包长度字段 (authenticated_len, packet_info[6])
- 清洗: `if (chunk_len > 0x800) chunk_len = 2048;` — 被限制上限
```
├── [L9506] authenticated_len = packet_info[6] 🔴 TAINTED
├── [L9513] chunk_len = authenticated_len - processed_len 🔴 TAINTED
│   └── [L9515] if (chunk_len > 0x800) chunk_len = 2048; 🟢 CLEANED (capped)
├── [L9519] MBUF_MakeMemoryContinuous_fl(..., chunk_len) ⚠️ chunk_len 控制读取大小
└── [L9534, L9576, L9960, L10002] AUTH_UPDATE(..., ..., chunk_len/auth_hash_len)
    └── ⚠️ DIRECT_SINK: 长度参数传入函数指针调用
```

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| auth_desc | *(auth_desc+28) 函数指针解引用 | L9534, L9576, L9960, L10002 | 可导致任意代码执行 |
| auth_state[0] | *(auth_desc+28) 第一参数 | L9534, L9576, L9960, L10002 | 状态句柄受控 |
| chunk | *(auth_desc+28) data_ptr | L9534, L9960 | mbuf 网络数据传入回调 |
| computed_auth | *(auth_desc+28) data_ptr | L9576, L10002 | HMAC 结果传入回调 |
| chunk_len | *(auth_desc+28) data_len | L9534, L9960 | 读取大小可控（已限制2048） |
| RAW_U16(desc,14) | *(auth_desc+28) data_len | L9576, L10002 | 长度字段完全可控 |
| chunk_len | MBUF_MakeMemoryContinuous_fl size | L9519, L9957 | 长度控制从 mbuf 读取的字节数 |
| auth_desc+36 | *(auth_desc+36) 函数指针 | L9577, L10003 | 最终验证函数指针 |

## 新导入的污点载体 (从其他函数引入)

| 新对象 | 来源函数 | 用途 |
|--------|---------|------|
| auth_state[0] | AUTH_INIT | 状态上下文句柄，传入 AUTH_UPDATE |
| computed_auth | AUTH_FINAL | HMAC 结果，作为第二阶段 AUTH_UPDATE 的 data_ptr |
| chunk (derived) | MBUF_MakeMemoryContinuous_fl | mbuf 网络数据，作为第一阶段 AUTH_UPDATE 的 data_ptr |

## 关键 DIRECT_SINK 模式

```
⚠️ DIRECT_SINK: *(auth_desc+28)(auth_state, data_ptr, data_len)
   - 函数指针 *(auth_desc+28) 来自外部 SADB 输入
   - auth_state 由 AUTH_INIT 从 SADB 数据初始化
   - data_ptr 为网络包负载 (chunk) 或 HMAC 结果 (computed_auth)
   - data_len 来自网络包字段或 RAW_U16(auth_desc,14)
   - 任意参数组合均可导致任意代码执行

⚠️ DIRECT_SINK: *(auth_desc+36)(computed_auth, auth_state, lib_ctx, out_len)
   - 最终验证回调函数指针可控
```

---

## [60/61] IPSECL_DBG_EspPktAlgoV4  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `lib_ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `flow_id=dbg_flow_id` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `algo_word=packet_info[14]` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSECL_DBG_EspPktAlgoV4

## 函数信息
- 文件: libipsec.c
- 签名: `void IPSECL_DBG_EspPktAlgoV4(void *lib_ctx, esp_sa_stats *sa_stats, unsigned int flow_id, unsigned int *packet_meta)`
- 功能: ESP包算法调试信息输出，处理IPsec库上下文和ESP安全关联统计

---

## 污点源汇总

| 污点变量 | 类型 | 来源 | 说明 |
|---------|------|------|------|
| `lib_ctx` | void* | 外部库上下文指针，来自网络/IPsec库初始化 | 🔴 TAINTED |
| `flow_id` | unsigned int | `__builtin_bswap32(packet_info[13])`，网络包中的SPI/flow selector | 🔴 TAINTED |
| `packet_meta` | unsigned int* | 外部污点对象 `&algo_dbg_word` 传入，承载 packet_info[14] | 🔴 TAINTED |

---

## 新导入的污点对象（函数内部派生）

| 对象 | 类型 | 来源 | 行号 |
|-----|------|------|------|
| `dbg_mode` | unsigned int | `*((uint8_t*)packet_meta + 4)` 从 packet_meta+4 提取 | L8199 |
| `dbg_tag` | unsigned int | `*packet_meta` 从 packet_meta 提取 | L8200 |

---

## 传播路径

### INPUT-1: lib_ctx (void*) 🔴 TAINTED
```
lib_ctx 🔴 TAINTED
├── [L8197] if (lib_ctx) → 条件判断
├── [L8198] RAW_U8((void *)lib_ctx, 401) == 1 → 🟡 CONTROL_USED（调试模式标志）
│   ├── [L8210] IPSEC_PKT_DebugPacketV4(lib_ctx, sa_stats, flow_id, dbg_mode, dbg_tag) → 📎 子函数
│   ├── [L8220] IPSEC_MakeDbgLibStrSetter(lib_ctx, ..., algo_word, ...) → 📎 子函数
│   └── [L8223] SSP_Debug(..., (const char *)(lib_ctx + 448)) → ⚠️ DIRECT_SINK
├── [L8203] RAW_U8((void *)lib_ctx, 403) != 1 → 🟡 CONTROL_USED
│   └── [L8214] IPSEC_PKT_DebugPacketV4(lib_ctx, sa_stats, flow_id, dbg_mode, dbg_tag) → 📎 子函数
├── [L8229] if (lib_ctx) → 条件判断
├── [L8258] if (lib_ctx) → 条件判断
├── [L8259] RAW_U8((void *)lib_ctx, 401) == 1 → 🟡 CONTROL_USED
│   └── [L8269] IPSEC_PKT_DebugPacketV4(...) → 📎 子函数
├── [L8264] RAW_U8((void *)lib_ctx, 403) != 1 → 🟡 CONTROL_USED
│   └── [L8271] IPSEC_PKT_DebugPacketV4(...) → 📎 子函数
├── [L8279] IPSEC_MakeDbgLibStrSetter(lib_ctx, ..., algo_word, ...) → 📎 子函数
├── [L8300] if (lib_ctx) → 条件判断
├── [L8301] RAW_U8((void *)lib_ctx, 401) == 1 → 🟡 CONTROL_USED
│   └── [L8337] IPSEC_PKT_DebugPacketV4(...) → 📎 子函数
├── [L8306] RAW_U8((void *)lib_ctx, 403) == 1 → 🟡 CONTROL_USED
├── [L8313] RAW_U8((void *)lib_ctx, 401) == 1 → 🟡 CONTROL_USED
│   └── [L8317] IPSEC_PKT_DebugPacketV4(...) → 📎 子函数
├── [L8320] RAW_U8((void *)lib_ctx, 403) != 1 → 🟡 CONTROL_USED
├── [L8321] IPSEC_PKT_DebugPacketV4(...) → 📎 子函数
├── [L8327] IPSEC_MakeDbgLibStrSetter(lib_ctx, ..., algo_word, ...) → 📎 子函数
├── [L8328] SSP_Debug(..., (const char *)(lib_ctx + 448)) → ⚠️ DIRECT_SINK
├── [L8335] RAW_U8((void *)lib_ctx, 401) == 1 → 🟡 CONTROL_USED
├── [L8342] result = RAW_U8((void *)lib_ctx, 403) → 🟡 CONTROL_USED
│   └── [L8346] IPSEC_PKT_DebugPacketV4(...) → 📎 子函数
├── [L8351] IPSEC_MakeDbgLibStrSetter(lib_ctx, ..., algo_word, ...) → 📎 子函数
└── [L8352] SSP_Debug(..., (const char *)(lib_ctx + 448)) → ⚠️ DIRECT_SINK
```

### INPUT-2: flow_id (unsigned int) 🔴 TAINTED
```
flow_id 🔴 TAINTED
├── [L8210] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数（sa_type==3分支）
├── [L8215] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数
├── [L8246] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数（sa_type==5分支）
├── [L8251] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数
├── [L8269] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数（默认分支）
├── [L8276] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数
├── [L8286] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数（after_sa_type_log分支）
├── [L8291] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数
├── [L8302] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数（auth_alg_log分支）
└── [L8308] IPSEC_PKT_DebugPacketV4(..., flow_id, ...) → 📎 子函数
```

### INPUT-3: packet_meta (unsigned int*) 🔴 TAINTED
```
packet_meta 🔴 TAINTED
├── [L8199] dbg_mode = *((uint8_t*)packet_meta + 4);
│   └── dbg_mode 🔴 TAINTED
│       └── [L8210,L8214,L8215,L8246,L8251,L8269,L8271,L8276,L8286,L8291,L8302,L8308,L8317,L8321,L8337,L8346]
│           共16次传入 IPSEC_PKT_DebugPacketV4 → 📎 子函数
└── [L8200] dbg_tag = *packet_meta;
    └── dbg_tag 🔴 TAINTED
        └── [L8210,L8214,L8215,L8246,L8251,L8269,L8271,L8276,L8286,L8291,L8302,L8308,L8317,L8321,L8337,L8346]
            共16次传入 IPSEC_PKT_DebugPacketV4 → 📎 子函数
```

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| lib_ctx | ⚠️ DIRECT_SINK | L8223 | lib_ctx+448 作为 (const char*) 传入 SSP_Debug |
| lib_ctx | ⚠️ DIRECT_SINK | L8328 | 同上 |
| lib_ctx | ⚠️ DIRECT_SINK | L8352 | 同上 |
| lib_ctx | 🟡 CONTROL_USED | L8198,L8203,L8259,L8264,L8301,L8306,L8313,L8320,L8335,L8342 | 调试模式标志用于条件分支 |
| lib_ctx | 📎 子函数 | 16处 | 传递给调试和日志函数 |
| flow_id | 📎 子函数 | 10处 | 作为只读参数传递给 IPSEC_PKT_DebugPacketV4 |
| dbg_mode | 📎 子函数 | 16处 | 作为参数传递给 IPSEC_PKT_DebugPacketV4 |
| dbg_tag | 📎 子函数 | 16处 | 作为参数传递给 IPSEC_PKT_DebugPacketV4 |

---

## [61/61] AUTH_FINAL  ·  被跟入函数

## Upstream Entry Hints

| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `auth_desc` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `computed_auth` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `auth_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `lib_ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: AUTH_FINAL

## 函数信息
- 文件: libipsec.c
- 函数名: AUTH_FINAL
- 污点输入参数:
  - `auth_desc` (uint32_t*) 🔴 TAINTED — 从 SA 数据库查询，SPI 来自外部网络输入
  - `computed_auth` (uint8_t[64]) 🔴 TAINTED — 由 AUTH_FINAL 宏输出（初始由调用者传入）
  - `auth_state[0]` 🔴 TAINTED — 由 AUTH_UPDATE 累积网络包数据
  - `lib_ctx` 🔴 TAINTED — 外部网络上下文参数

## 新导入的污点对象 (Within AUTH_FINAL)

| 变量 | 类型 | 污点来源 | 行号 |
|------|------|----------|------|
| `computed_auth` | uint8_t[64] | AUTH_FINAL 宏写入 out_buf | L9573, L9577, L9999, L10003 |
| `received_auth` | uint8_t[64] | MBUF_CopyDataFromMBufToBuffer 写入 | L9504, L1088 |

## 数据流树状图

### INPUT-1: auth_desc (uint32_t*) 🔴 TAINTED
├── [L498] AUTH_INIT(auth_desc, state, sa_entry, 1)
│   └── ⚠️ DIRECT_SINK: auth_desc+44 指针算术 → 虚函数查找
├── [L573] AUTH_FINAL(auth_desc, computed_auth, ...)
│   ├── ⚠️ DIRECT_SINK: auth_desc+36 指针算术 → 虚函数查找
│   └── computed_auth ← 🔴 TAINTED (算法输出)
├── [L576] AUTH_UPDATE(auth_desc, state, computed_auth, RAW_U16(auth_desc,14))
│   ├── computed_auth 🔴 TAINTED → 作为算法输入
│   ├── RAW_U16(auth_desc,14) 🔴 TAINTED → 从 tainted 结构读长度
│   └── ⚠️ DIRECT_SINK: auth_desc+28 指针算术 → 虚函数查找
└── [L579] VOS_MemCmp(computed_auth, received_auth, ...)
    └── 📌 USED: computed_auth 🔴 TAINTED 参与认证比较

### INPUT-2: computed_auth (uint8_t[64]) 🔴 TAINTED
├── [L9573] AUTH_FINAL(auth_desc, computed_auth, ..., 64)
│   └── computed_auth ← 🔴 TAINTED (新导入对象)
├── [L9575] AUTH_INIT(auth_desc, ..., sa_entry, 0) — 重新初始化
├── [L9577] AUTH_UPDATE(auth_desc, auth_state[0], computed_auth, RAW_U16(auth_desc+14))
│   ├── computed_auth 🔴 TAINTED → 作为 data_ptr 传入
│   └── ⚠️ DIRECT_SINK: data_len 由 auth_desc+14 提供（attacker-controlled）
├── [L9579] AUTH_FINAL(auth_desc, computed_auth, ..., 64)
│   └── ⚠️ DIRECT_SINK: 再次写入 computed_auth
└── [L9582] VOS_MemCmp(computed_auth, received_auth, auth_hash_len_field)
    └── 📌 USED: 用于认证结果比较判断

### INPUT-3: auth_state[0] 🔴 TAINTED
├── [L9498] AUTH_INIT(state) → 用 sa_entry 数据初始化
├── [L9534] AUTH_UPDATE(auth_state[0], chunk, chunk_len)
│   └── auth_state[0] 累积网络包数据
├── [L9573] AUTH_FINAL(..., (int64_t)auth_state[0], ...)
│   ├── computed_auth ← 🔴 TAINTED (新导入对象)
│   └── ⚠️ DIRECT_SINK: auth_state[0] 作为 state_handle 传入外部函数
│       └── 🟡 EXPORT: 外部函数指针目标未知
├── [L9575] AUTH_INIT(state) → 状态重新初始化
├── [L9576] AUTH_UPDATE(auth_state[0], computed_auth, ...)
│   ├── auth_state[0] 包含 computed_auth
│   └── ⚠️ DIRECT_SINK: computed_auth 作为 data_ptr
└── [L9577] AUTH_FINAL(..., (int64_t)auth_state[0], ...)
    └── ⚠️ DIRECT_SINK: 同上风险

### INPUT-4: lib_ctx 🔴 TAINTED
├── [L9378] RAW_U64((void *)lib_ctx, 16) → offset 🔴 TAINTED
│   └── MBUF_MakeMemoryContinuous_fl(..., offset, ...)
│       ⚠️ DIRECT_SINK: offset由lib_ctx+16控制,可能导致内存访问越界
├── [L9396] RAW_U64((void *)lib_ctx, 16) → 再次作为MBUF偏移参数
│   └── MBUF_MakeMemoryContinuous_fl(mbuf, offset, 24, ...)
├── [L9410] RAW_U8((void *)lib_ctx, 400/403)
│   └── 条件判断 → 🟢 不传播
├── [L9419] VOS_AVL3_Find(lib_ctx+120, &key, lib_ctx+144)
│   └── SA查找参数
├── [L9434] VOS_AVL3_Find(lib_ctx+76, ptr, lib_ctx+100)
│   └── SADB查找参数
├── [L9524] RAW_U64((void *)lib_ctx, 16) → chunk连续化偏移
│   └── chunk = MBUF_MakeMemoryContinuous_fl(..., chunk_len, offset, ...)
├── [L9573] AUTH_FINAL(..., lib_ctx, 64)
│   ├── lib_ctx 作为第3参数传入虚函数
│   └── ⚠️ DIRECT_SINK: 间接虚函数调用
└── [L9581] (const char *)(lib_ctx + 448) → SSP_Debug(...)
    └── 调试字符串参数

### New Tainted Object: received_auth 🔴 TAINTED (新导入)
├── [L9504/L1088] MBUF_CopyDataFromMBufToBuffer(mbuf, ..., received_auth)
│   └── 从网络包复制 auth_hash_len 字节
└── [L579/L9582] VOS_MemCmp(computed_auth, received_auth, ...)
    └── 📌 USED: 参与认证比较

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `auth_desc` | ⚠️ DIRECT_SINK | L498, L573, L576 | 指针算术+虚函数查找 |
| `auth_state[0]` | ⚠️ DIRECT_SINK | L9573, L9577 | 作为函数指针参数，可能被外部密码库解引用 |
| `auth_state[0]` | 📌 USED | L9534, L9576 | 参与 HMAC 计算 |
| `computed_auth` | ⚠️ DIRECT_SINK | L9577, L10002 | 作为 AUTH_UPDATE 的 data_ptr |
| `computed_auth` | 📌 USED | L579, L9582, L10006 | 与 received_auth 做认证校验 |
| `lib_ctx+16` | ⚠️ DIRECT_SINK | L9378, L9396, L9524 | 作为 MBUF 偏移参数，越界访问风险 |

## 安全风险

### ⚠️ 高危 DIRECT_SINK 汇总

1. **间接函数调用 (L9573, L9577, L9999, L10003)**
   - AUTH_FINAL 通过 `auth_desc+36` 函数指针表间接调用
   - auth_desc 来自外部 SA 条目，可被攻击者覆写
   - 风险: 控制流劫持 → 代码执行

2. **外部函数指针解引用 (L9573, L9577)**
   - `auth_state[0]` 作为 `state_handle`（int64_t）传入外部密码库
   - 如果外部函数将其解释为指针而未做验证
   - 风险: 越界内存访问、信息泄露、认证绕过

3. **MBUF 偏移参数 (L9378, L9396, L9524)**
   - `RAW_U64((void *)lib_ctx, 16)` 作为内存连续化请求的偏移量
   - 若 lib_ctx+16 处值被污染，可能导致越界内存访问
   - 风险: 内存越界访问 → 信息泄露/损坏

4. **Attacker-controlled length field (L576, L9576, L10002)**
   - `RAW_U16(auth_desc, 14)` 提供 data_len 参数
   - auth_desc 来自外部 SA 条目，长度字段可控
   - 风险: 缓冲区溢出、数据截断

---