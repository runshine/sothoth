## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `receive_if_index` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_PKT_DebugPacket

## 函数信息
- 文件: `core/ipsec/libipsec.c`
- 函数: `IPSEC_PKT_DebugPacket`
- 行号: L10240–L10275
- 签名: `int64_t IPSEC_PKT_DebugPacket(int64_t a1, int64_t a2, int64_t a3, int64_t a4, int64_t a5, uint32_t packet_kind)`

## 数据流树状图

### INPUT-1: packet_kind (uint32_t) 🔴 TAINTED
来源: 调用者 `IPSEC_LIBI_HandleInputPkt` 传入，值来自 `MBUF_GetReceiveIfIndex(mbuf, ...)` 提取的网络包接收接口索引（L11012处），经 `receive_if_index` 变量直接传参

```
packet_kind 🔴 TAINTED
└── [L10257] kind_filter != (uint32_t)packet_kind — 仅参与 uint32_t 数值比较，无 memcpy/sprintf/数组索引/指针运算
```

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| packet_kind | USED | L10257 | 与 kind_filter 的 uint32_t 数值比较，用于过滤调试日志输出条件判断 |

## 安全备注
- `packet_kind` 仅参与 uint32_t 数值比较，**未检测到 DIRECT_SINK**
- 无 memcpy/sprintf/数组索引/指针运算等危险操作
- 污点数据在函数内部未传播至其他变量或子函数调用