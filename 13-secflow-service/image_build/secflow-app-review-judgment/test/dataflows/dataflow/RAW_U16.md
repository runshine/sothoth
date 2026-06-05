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