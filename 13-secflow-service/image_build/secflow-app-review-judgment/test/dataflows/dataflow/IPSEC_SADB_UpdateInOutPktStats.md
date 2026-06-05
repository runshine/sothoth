## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `a2` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `a3` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `a4` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SADB_UpdateInOutPktStats

## 函数信息
- 文件: libipsec.c
- 行号: L15268-L15324
- 签名: `int IPSEC_SADB_UpdateInOutPktStats(uint32_t *a2, unsigned int a3, int a4)`

## 污点源

| ID | 参数名 | 类型 | 污点等级 | 说明 |
|----|--------|------|----------|------|
| INPUT-1 | a2 | uint32_t* | 🔴 TAINTED | 外部指针参数,指向统计数组缓冲区 |
| INPUT-2 | a3 | unsigned int | 🔴 TAINTED | 外部输入参数,用于条件分支判断 |
| INPUT-3 | a4 | int | 🔴 TAINTED | 外部输入参数,用于累加到统计数组 |

## 数据流树状图

### INPUT-1: a2 (uint32_t*) 🔴 TAINTED
```
a2 🔴 TAINTED
├── [L15269] if (a2) ++a2[1011]  → a2[1011] 🔴 TAINTED write
├── [L15272] if (a2) ++a2[1007]  → a2[1007] 🔴 TAINTED write
├── [L15274] if (a2) ++a2[1005]  → a2[1005] 🔴 TAINTED write
├── [L15276] if (a2) ++a2[1006]  → a2[1006] 🔴 TAINTED write
├── [L15281] if (a2) ++a2[1009]  → a2[1009] 🔴 TAINTED write
├── [L15284] if (a2) ++a2[1010]  → a2[1010] 🔴 TAINTED write
├── [L15286] if (a2) ++a2[1008]  → a2[1008] 🔴 TAINTED write
├── [L15289] if (a2) a2[1016] += a4  → a2[1016] 🔴 TAINTED write (合并a4)
├── [L15294] if (a2) ++a2[1020]  → a2[1020] 🔴 TAINTED write
├── [L15297] if (a2) ++a2[1021]  → a2[1021] 🔴 TAINTED write
├── [L15300] if (a2) a2[1017] += a4  → a2[1017] 🔴 TAINTED write (合并a4)
├── [L15306] if (a2) ++a2[1013]  → a2[1013] 🔴 TAINTED write
├── [L15309] if (a2) ++a2[1012]  → a2[1012] 🔴 TAINTED write
└── [L15312] if (a2) ++a2[1014]  → a2[1014] 🔴 TAINTED write
```

### INPUT-2: a3 (unsigned int) 🔴 TAINTED
```
a3 🔴 TAINTED
└── [L15270–L15319] 条件判断（14 处 if/else-if/switch 比较）
    ├── `a3 == 16` → L15271–L15272: `++a2[1011]`, `++result[57]`（常量下标）
    ├── `a3 <= 0x10` → L15274–L15293: 分支内使用编译期常量下标
    │   ├── `a3 == 12` → L15275–L15276: `++a2[1007]`, `++result[53]`
    │   ├── `a3 <= 0xC` → L15278–L15283: 下标 1005/1006/1008
    │   ├── `a3 == 14` → L15286–L15287: `++a2[1009]`, `++result[55]`
    │   └── `a3 > 0xE` → L15289–L15290: `++a2[1010]`, `++result[56]`
    ├── `a3 == 21` → L15296–L15297: `a2[1016] += a4`, `result[62] += a4`
    ├── `a3 > 0x15` → L15300–L15311: switch(0x16/0x19/0x1A)，常量下标
    ├── `a3 == 18` → L15314–L15315: `++a2[1013]`, `++result[59]`
    ├── `a3 < 0x12` → L15317–L15318: `++a2[1012]`, `++result[58]`
    └── `a3 == 19` → L15320–L15321: `++a2[1014]`, `++result[60]`
        └── [L15323] `return result` — result 本身非 a3，a3 未写入返回值

⚠️ 注：所有数组下标均为编译期常量，a3 仅决定进入哪个分支，不直接参与下标计算
```

### INPUT-3: a4 (int) 🔴 TAINTED
```
a4 🔴 TAINTED
├── [L15297] a3 == 21 时
│   ├── `a2[1016] += a4` → a2[1016] 🔴 TAINTED
│   └── `result[62] += a4` → result[62] 🔴 TAINTED
└── [L15307] a3 == 0x16 时
    ├── `a2[1017] += a4` → a2[1017] 🔴 TAINTED
    └── `result[63] += a4` → result[63] 🔴 TAINTED
```

## 新导入的污点对象（函数内部产生）

| 污点对象 | 类型 | 产生位置 | 来源 | 说明 |
|---------|------|---------|------|------|
| a2[1016] | uint32_t | L15289 | `a2[1016] += a4` | a4 累加到 a2 数组 |
| a2[1017] | uint32_t | L15300 | `a2[1017] += a4` | a4 累加到 a2 数组 |
| result[62] | uint32_t | L15289 | `result[62] += a4` | a4 累加到 result 数组 |
| result[63] | uint32_t | L15300 | `result[63] += a4` | a4 累加到 result 数组 |

## 污点终点汇总

| 脏数据 | 终点类型 | 位置 | 说明 |
|--------|----------|------|------|
| a2 | WRITE | L15269-L15312 | 14处写入统计数组 (常量下标) |
| a3 | CONDITIONAL | L15270-L15319 | 14处条件分支判断 |
| a4 | WRITE | L15289, L15300 | 累加到 a2[1016/1017] 和 result[62/63] |

## 接收此污点的子函数

| 文件 | 函数 | 调用行 | 接收的形参 |
|------|------|--------|----------|
| (无) | - | - | 本函数内无任何子函数调用，所有操作均为内联语句 |

## DIRECT_SINK 标记

无 DIRECT_SINK 风险 — a3 仅用于条件分支判断，所有数组下标均为编译期常量