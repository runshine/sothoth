## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_SOCK_SendToSocket

## 函数信息
- 文件: libipsec.c
- 签名: `void IPSEC_SOCK_SendToSocket(int aSocket, struct mbuf *ambuf, int aFlags)`

## 污点源
| 参数 | 类型 | 状态 |
|------|------|------|
| mbuf | struct mbuf* | 🔴 TAINTED - 外部网络输入，socket mbuf 包含从网络接收的分组数据 |

## 传播路径

### mbuf 🔴 TAINTED
```
├── [L24685-24688] mbuf == 0 → 条件判断，无传播
├── [L24752] SOCK_MBufForwardTokenAlloc_fl(mbuf, ...) → 句柄传递，不提取载荷
├── [L24795] base_ctl = MBUF_GetControlInfo(mbuf, 0) → base_ctl 🔴 TAINTED
│   └── [L24827-24830] base_ctl值拷贝到 ctl_blob → ctl_blob 🔴 TAINTED
├── [L24860] ip_ctl = MBUF_GetControlInfo(mbuf, 8) → ip_ctl 🔴 TAINTED（新载体）
│   ├── [L24864] IPSEC_MBUF_GetIPFlag6(ctl_blob+4, ip_ctl) → ctl_blob 🔴 TAINTED
│   ├── [L24874] memcpy_s(ctl_blob+36, 16, ip_ctl+16, 16) ⚠️ DIRECT_SINK
│   │   └── 污点IP字段（来自mbuf）复制到栈缓冲区，无边界校验
│   ├── [L24878] memcpy_s(ctl_blob+20, 16, ip_ctl, 16) ⚠️ DIRECT_SINK
│   │   └── 源/目的IP从污点ip_ctl复制到固定大小栈缓冲区
│   └── [L24885-24893] RAW_U16(ip_ctl, 32/34) → ctl_blob[52/54] 🔴 TAINTED
│       └── 端口号（污点）写入栈缓冲区
├── [L24902] IPSEC_SOCK_CopyDbgTracePacket(..., mbuf, &trace_len, &trace_buf) → trace_buf 🔴 TAINTED（新载体）
│   └── mbuf分组数据复制到trace_buf
│       └── [L24912] IPSEC_SOCK_DbgTracePacket(ctx_base, ctl_blob, trace_buf, ...) → trace_buf传入调试函数
├── [L24936] ip_ctl = MBUF_GetControlInfo(mbuf, 2) → ip_ctl 🔴 TAINTED（覆盖）
│   └── [L24940] IPSEC_MBUF_GetIPFlag(ctl_blob+4, ip_ctl) → ctl_blob 🔴 TAINTED
│   └── [L24947-24950] RAW_U16/RAW_U32(ip_ctl, ...) → ctl_blob[...] 🔴 TAINTED
├── [L24952] IPSEC_SOCK_CopyDbgTracePacket(..., mbuf, ...) → trace_buf 🔴 TAINTED
├── [L24974] SOCK_SetMbufCtlInfoEx_fl(mbuf, ctl_blob, ...) → mbuf携带ctl_blob写入
└── [L24985] MBUF_Send_fl(..., mbuf, ...) → 📌 USED（最终发送mbuf到socket）
```

## 新导入的污点对象

| 变量名 | 引入位置 | 来源 | 说明 |
|--------|---------|------|------|
| base_ctl | L24795 | MBUF_GetControlInfo(mbuf, 0) | 控制信息提取 |
| ip_ctl | L24860 | MBUF_GetControlInfo(mbuf, 8) | IPv6控制信息 |
| ip_ctl | L24936 | MBUF_GetControlInfo(mbuf, 2) | IPv4控制信息（覆盖） |
| ctl_blob | L24827-24893 | ip_ctl/base_ctl数据写入 | 栈缓冲区84字节，承载污点IP/端口字段 |
| trace_buf | L24902/L24952 | IPSEC_SOCK_CopyDbgTracePacket输出 | 调试跟踪缓冲区，承载mbuf分组数据 |

## 高危操作汇总

| 类型 | 位置 | 说明 |
|------|------|------|
| ⚠️ DIRECT_SINK | L24874 | memcpy_s 目标指针和大小与污点数据相关，IP字段复制到栈缓冲区 |
| ⚠️ DIRECT_SINK | L24878 | memcpy_s 从污点ip_ctl复制源/目的IP到固定大小栈缓冲区 |
| 📌 USED | L24985 | MBUF_Send_fl 将污点mbuf发送到socket |

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf | MBUF_Send_fl | L24985 | 最终发送污点数据到socket |
| ctl_blob | SOCK_SetMbufCtlInfoEx_fl | L24974 | 控制信息写入mbuf |
| trace_buf | IPSEC_SOCK_DbgTracePacket | L24912 | 调试跟踪函数消费 |

## 子函数跟入列表

| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| MBUF_GetControlInfo | L24795 | mbuf |
| MBUF_GetControlInfo | L24860 | mbuf |
| MBUF_GetControlInfo | L24936 | mbuf |
| SOCK_MBufForwardTokenAlloc_fl | L24752 | mbuf |
| IPSEC_SOCK_CopyDbgTracePacket | L24902 | mbuf |
| IPSEC_SOCK_CopyDbgTracePacket | L24952 | mbuf |
| IPSEC_SOCK_DbgTracePacket | L24912 | trace_buf |
| SOCK_SetMbufCtlInfoEx_fl | L24974 | mbuf, ctl_blob |
| MBUF_Send_fl | L24985 | mbuf |