## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `common_info` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SOCK_GetLdmPipeLC

## 函数信息
- 文件: libipsec.c
- 签名: `void* IPSEC_SOCK_GetLdmPipeLC(void* ctx_base, void* pid_ptr)`

## 污点源
| 变量 | 类型 | 来源 | 说明 |
|------|------|------|------|
| common_info | void* | MBUF_GetControlInfo(mbuf, 9) | 🔴 TAINTED — 从网络包控制信息中提取的外部输入 |

## 传播路径

### INPUT-1: common_info (void*) 🔴 TAINTED
```
[污点来源]
  MBUF_GetControlInfo(mbuf, 9)
        ↓
[L26773] 传入参数: IPSEC_SOCK_GetLdmPipeLC(ctx_base, common_info)
        ↓
[当前函数: IPSEC_SOCK_GetLdmPipeLC]
        ↓
[L26502] *node != *pid_ptr
        └── *pid_ptr 解引用参与AVL树节点比较 🔴 TAINTED
        ↓
[L26509] *pid_ptr != *candidate
        └── *pid_ptr 在循环中与候选节点比较 🔴 TAINTED
        ↓
[终点] 函数内部使用，无外部传播
```

## 污点终点汇总
| 变量 | 终点 | 位置 | 说明 |
|------|------|------|------|
| common_info (*pid_ptr) | 📌 USED | L26502 | AVL树节点比较运算 |
| common_info (*pid_ptr) | 📌 USED | L26509 | 循环中与候选节点比较 |

## 新导入污点对象
无新对象导入 — common_info 是从外部传入的已有污点载体

## 备注
- 当前函数为污点数据的最终消费者
- common_info 被解引用后参与树结构比较操作
- 无进一步污点传播至其他函数