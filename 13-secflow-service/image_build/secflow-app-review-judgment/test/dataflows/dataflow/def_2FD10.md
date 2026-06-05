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