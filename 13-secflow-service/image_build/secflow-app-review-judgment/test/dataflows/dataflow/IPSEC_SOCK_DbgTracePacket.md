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