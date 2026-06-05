## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIBI_HandleInputPkt

## 函数信息
- 文件: libipsec.c
- 函数: `IPSEC_LIBI_HandleInputPkt`
- 污点类型: 🔴 TAINTED - 外部网络数据包

---

## 污点源

| 名称 | 类型 | 说明 |
|------|------|------|
| mbuf | mbuf* | 🔴 TAINTED - 外部网络数据包缓冲区 |

---

## 传播路径

```
### INPUT: mbuf (mbuf*) 🔴 TAINTED
│
├── [L11009] receive_if_index = MBUF_GetReceiveIfIndex(mbuf, ...) → receive_if_index 🔴 TAINTED
│   └── 说明: 从mbuf中提取接收接口索引，产生新的污点载体
│   └── 用途: 用于调试/诊断操作（仅控制流，无直接Sink风险）
│
├── [L11027] IPSEC_PKT_ParseAndVerifyHdr(mbuf, lib_ctx, parse_state) 📎
│   └── 参数: mbuf (🔴 TAINTED)
│   └── 说明: 从mbuf中解析并验证IPsec头部
│
├── [L11069] IPSEC_AH_HandleInputPkt(lib_ctx, mbuf, parse_state) 📎
│   └── 参数: mbuf (🔴 TAINTED)
│   └── 说明: 处理AH（认证头）入站数据包
│
└── [L11113] IPSEC_ESP_HandleInputPkt(lib_ctx, mbuf, parse_state) 📎
    └── 参数: mbuf (🔴 TAINTED)
    └── 说明: 处理ESP（封装安全载荷）入站数据包
```

---

## 新增污点载体追踪

| 污点载体 | 来源 | 行号 | 说明 |
|----------|------|------|------|
| receive_if_index | MBUF_GetReceiveIfIndex() | L11009 | 从mbuf提取的接收接口索引 |

**receive_if_index 用途分析**:
- 用于调试/诊断操作
- 仅参与控制流判断
- 无直接 Sink 消费

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mbuf | IPSEC_PKT_ParseAndVerifyHdr | L11027 | 解析IPsec头部 |
| mbuf | IPSEC_AH_HandleInputPkt | L11069 | 处理AH入站数据包 |
| mbuf | IPSEC_ESP_HandleInputPkt | L11113 | 处理ESP入站数据包 |

---

## 调用子函数清单

| 序号 | 函数 | 调用行 | 接收参数 | 性质 |
|------|------|--------|----------|------|
| 1 | IPSEC_PKT_ParseAndVerifyHdr | L11027 | mbuf | 📎 见跟入列表 |
| 2 | IPSEC_AH_HandleInputPkt | L11069 | mbuf | 📎 见跟入列表 |
| 3 | IPSEC_ESP_HandleInputPkt | L11113 | mbuf | 📎 见跟入列表 |

---

## 备注

- **污点类型**: 外部网络输入（不可信数据包）
- **安全边界**: 本函数为IPsec处理入口，需要对mbuf内容进行严格验证
- **传播方向**: mbuf作为核心参数传递至多个处理子函数