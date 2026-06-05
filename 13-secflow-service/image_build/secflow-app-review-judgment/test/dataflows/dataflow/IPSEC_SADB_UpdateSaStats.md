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