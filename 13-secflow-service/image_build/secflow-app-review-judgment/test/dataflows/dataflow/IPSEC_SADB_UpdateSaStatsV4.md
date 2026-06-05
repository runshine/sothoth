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