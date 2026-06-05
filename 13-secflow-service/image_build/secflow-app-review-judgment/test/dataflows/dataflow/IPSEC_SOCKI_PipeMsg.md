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