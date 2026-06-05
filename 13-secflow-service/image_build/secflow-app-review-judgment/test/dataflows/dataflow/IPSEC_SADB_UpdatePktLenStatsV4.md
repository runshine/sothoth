## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `result` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SADB_UpdatePktLenStatsV4

## 函数信息
- 文件: libipsec.c
- 函数签名: `int64_t IPSEC_SADB_UpdatePktLenStatsV4(int64_t result, int64_t a2, int a3)`
- 函数功能: 更新IPv4包长统计，通过将传入的整数值强制转换为指针并进行内存写操作

## 污点源

| 输入参数 | 类型 | 状态 | 说明 |
|---------|------|------|------|
| result | int64_t | 🔴 TAINTED | 外部调用者传入的整数，被强制转换为指针使用 |

## 新导入的污点对象

| 变量 | 类型 | 导入方式 | 说明 |
|------|------|----------|------|
| 无 | — | — | 此函数无 Recv/Read/Decode/Parse 等数据导入调用 |

## 传播路径树状图

```
### INPUT: result (int64_t) 🔴 TAINTED - 外部调用者传入的整数，被强制转换为指针使用
├── [L15585] if (result) ++RAW_U32((void*)result, 372)
│   ⚠️ DIRECT_SINK: result 强转为 (uint8_t*) 并加上固定偏移 372，dereference 为 uint32_t* 后自增
│   → 攻击者通过 result 控制写操作的目标地址（任意内存写）
├── [L15588] if (result) ++RAW_U32((void*)result, 388)
│   ⚠️ DIRECT_SINK: 同上，目标地址 = result + 388，攻击者完全可控
└── [L15590] return result
    📌 USED: 作为 int64_t 返回值
```

## 子函数跟入列表

| 文件 | 函数 | 调用行 | 接收的形参 | 状态 |
|------|------|--------|-----------|------|
| — | — | — | — | 无子函数调用（两处危险操作均为内联宏 RAW_U32） |

## 污点终点汇总

| 污点数据 | 终点类型 | 位置 | 说明 |
|---------|---------|------|------|
| result | ⚠️ DIRECT_SINK | L15585 | `++RAW_U32((void*)result, 372)` — 宏展开为 `(*(uint32_t*)((uint8_t*)(result)+372))`，result 作为指针基址，攻击者可写任意内存 |
| result | ⚠️ DIRECT_SINK | L15588 | `++RAW_U32((void*)result, 388)` — 同上，目标地址为 result+388 |
| result | 📌 USED | L15590 | `return result` |

## 安全分析

RAW_U32 宏定义为：`(*(uint32_t*)((uint8_t*)(base) + (off)))`，两处调用均使用 result 作为 base 进行指针运算并写入内存。`if (result)` 仅排除零值，无法阻止指向任意用户可控地址的指针。