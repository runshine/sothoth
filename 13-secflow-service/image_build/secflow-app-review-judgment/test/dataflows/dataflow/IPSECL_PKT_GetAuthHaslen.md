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