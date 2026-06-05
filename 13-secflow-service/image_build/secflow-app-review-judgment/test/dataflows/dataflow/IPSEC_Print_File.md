## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_Print_File

## 函数信息
- 文件: libipsec.c
- 签名: `void IPSEC_Print_File(int64_t ctx, int flag, const char *text)`

## 污点源

| 参数 | 类型 | 污点状态 | 来源 |
|------|------|---------|------|
| ctx | int64_t | 🔴 TAINTED | 外部指针参数 a1 |

## 新导入的污点对象

无

## 传播路径

### ctx 🔴 TAINTED
```
[L19776] (void)ctx;
         └── 立即转换为void，无任何操作
         └── 无派生变量
         └── 无子函数调用
         └── 无sink触发
```
→ 函数结束，污点未使用

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| ctx | DISCARDED | L19776 | (void)ctx 立即丢弃，无数据流 |

## 接收此污点的子函数

无

## 备注

`IPSEC_Print_File` 是一个桩函数，空实现：

```c
void IPSEC_Print_File(int64_t ctx, int flag, const char *text)
{
    (void)ctx;
    (void)flag;
    (void)text;
}
```

污点参数 `ctx` 在函数内被立即丢弃，未被解引用、拷贝或传递到任何下游操作。无数据流。