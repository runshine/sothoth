## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `result` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: sub_2FD14

## 函数信息
- 文件: libipsec.c
- 行号: L15692-L15694
- 签名: `int64_t sub_2FD14(int64_t result)`

## 污点源
| 参数 | 类型 | 状态 | 说明 |
|------|------|------|------|
| result | int64_t | 🔴 TAINTED | 外部输入参数，调用者传入的指针 |

## 新导入的污点对象
无

## 传播路径

### INPUT-1: result (int64_t) 🔴 TAINTED
```
[L15692] if (result) → 条件判断，控制后续写操作是否执行
[L15693] ++RAW_U32((void *)result, 392) → ⚠️ DIRECT_SINK: 污点指针作为基址，
    写入偏移 392 字节处的 uint32 字段（整数增量写）
[L15694] return result → 📌 USED: 污点指针直接返回给调用者
```

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| result | ⚠️ DIRECT_SINK | L15693 | 污点指针作为基址，写入偏移 392 字节处的 uint32 字段 |
| result | 📌 USED | L15694 | 污点指针直接返回给调用者 |