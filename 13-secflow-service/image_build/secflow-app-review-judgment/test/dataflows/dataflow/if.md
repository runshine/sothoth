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