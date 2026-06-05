## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `ctx_base` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SOCK_GetLdmPipeMB

## 函数信息
- 文件: libipsec.c
- 签名: `void* IPSEC_SOCK_GetLdmPipeMB(void* ctx_base)`
- 功能: 从上下文基址获取LDM管道消息缓冲区指针

## 数据流树状图

### INPUT-1: ctx_base (void*) 🔴 TAINTED
├── [L24482] RAW_U32((void*)ctx_base, CTX_LDM_MB_PIPE_OFF) == 0 → 🟢 CLEANED (仅作分支条件，偏移量为编译时常量 1256)
└── [L24484] RAW_U32((void*)ctx_base, CTX_LDM_MB_PIPE_STATE_OFF) != 0 → 🟢 CLEANED (仅作分支条件，偏移量为编译时常量 1260)
    └── [L24486] return ctx_base + CTX_LDM_MB_PIPE_OFF → 🟢 CLEANED (偏移量 CTX_LDM_MB_PIPE_OFF=1256 为编译时常量，非用户数据派生)

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| ctx_base | 字段读取 | L24482 | CTX_LDM_MB_PIPE_OFF(1256) 偏移量编译时常量，仅作分支条件 |
| ctx_base | 字段读取 | L24484 | CTX_LDM_MB_PIPE_STATE_OFF(1260) 偏移量编译时常量，仅作分支条件 |
| ctx_base | 指针运算 | L24486 | 偏移量 1256 为编译时常量，未向返回值传播污点 |

## 新导入的污点对象
无

## 接收此污点的子函数
无

## 总结
`ctx_base` 仅被用于从固定偏移量读取 u32 值作为分支条件判断。偏移量 `CTX_LDM_MB_PIPE_OFF`(1256) 和 `CTX_LDM_MB_PIPE_STATE_OFF`(1260) 均为编译时常量，非用户数据派生，因此污点已清洗(🟢 CLEANED)。

函数返回值 `ctx_base + 1256` 的偏移量为编译时常量，污点未向返回值传播。本函数内无 ⚠️ DIRECT_SINK 操作。