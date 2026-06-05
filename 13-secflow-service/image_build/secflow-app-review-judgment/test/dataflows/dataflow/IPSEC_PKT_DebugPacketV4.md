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