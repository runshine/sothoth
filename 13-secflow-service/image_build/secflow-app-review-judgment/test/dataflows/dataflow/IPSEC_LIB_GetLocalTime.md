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