## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `algo_dbg_word` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `selector_pair` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `selector_pair_hi` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSECL_DBG_EspPktAlgo

## 函数信息
- 文件: libipsec.c
- 签名: `int64_t IPSECL_DBG_EspPktAlgo(int64_t lib_ctx, unsigned short **sa_type_desc, int64_t sadb_entry, int64_t selector1, int64_t selector2, unsigned int *packet_meta)`
- 功能: ESP包算法调试信息打印，接收网络报文元数据和选择器对

---

## 合并污点源 (4个外部输入)

| 序号 | 参数 | 类型 | 来源 |
|------|------|------|------|
| INPUT-1 | packet_meta | unsigned int* | 调用者通过 `packet_info[14]` 填充网络报文元数据 |
| INPUT-2 | selector1 | int64_t | 外部输入参数（第4形参），从 `packet_info[]` 构造 |
| INPUT-3 | selector2 | int64_t | 外部输入参数（第5形参），从 `packet_info[]` 构造 |
| INPUT-4 | dbg_mode | uint8_t | 从 packet_meta+4 提取的污点值 |
| INPUT-5 | dbg_tag | uint32_t | 从 packet_meta+0 提取的污点值 |

---

## 新导入的污点对象

- **无新污点对象导入**：函数内部未调用 Recv/Read/Recvfrom 等导入外部数据的函数
- 所有污点均来源于函数形参

---

## 传播路径

### INPUT-1: packet_meta (unsigned int*) 🔴 TAINTED
```
packet_meta 🔴 TAINTED
├── [L7970] dbg_tag = *packet_meta → dbg_tag 🔴 TAINTED
└── [L7969] dbg_mode = *((uint8_t *)packet_meta + 4) → dbg_mode 🔴 TAINTED
```

### INPUT-2: selector1 (int64_t) 🔴 TAINTED
```
selector1 🔴 TAINTED (第4形参，外部输入)
```

### INPUT-3: selector2 (int64_t) 🔴 TAINTED
```
selector2 🔴 TAINTED (第5形参，外部输入)
```

---

## 污点汇聚: 所有4个污点参数透传给 IPSEC_PKT_DebugPacket

**所有10处调用均传递完整的4个污点参数：**
```
IPSEC_PKT_DebugPacket(lib_ctx, sadb_entry, selector1, selector2, dbg_mode, dbg_tag)
```

| 调用位置 | 分支上下文 | 传递的污点参数 |
|----------|------------|----------------|
| L7980 | sa_type == 3 首次调用 | selector1, selector2, dbg_mode, dbg_tag |
| L7985 | sa_type == 3 重试 | selector1, selector2, dbg_mode, dbg_tag |
| L8011 | sa_type == 5 分支 | selector1, selector2, dbg_mode, dbg_tag |
| L8016 | sa_type == 5 重试 | selector1, selector2, dbg_mode, dbg_tag |
| L8053 | 默认分支 dbg_mode==1 | selector1, selector2, dbg_mode, dbg_tag |
| L8059 | 默认分支 dbg_mode==2 | selector1, selector2, dbg_mode, dbg_tag |
| L8069 | after_type_log dbg_mode==1 | selector1, selector2, dbg_mode, dbg_tag |
| L8075 | after_type_log dbg_mode==2 | selector1, selector2, dbg_mode, dbg_tag |
| L8088 | auth_log dbg_mode==1 | selector1, selector2, dbg_mode, dbg_tag |
| L8096 | auth_log dbg_mode==2 | selector1, selector2, dbg_mode, dbg_tag |

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| packet_meta | 📎 IPSEC_PKT_DebugPacket | L7980-L8096 (10处) | 网络报文元数据指针 |
| dbg_mode | 📎 IPSEC_PKT_DebugPacket | L7980-L8096 (10处) | 从 packet_meta+4 提取的 uint8 |
| dbg_tag | 📎 IPSEC_PKT_DebugPacket | L7980-L8096 (10处) | 从 packet_meta+0 提取的 uint32 |
| selector1 | 📎 IPSEC_PKT_DebugPacket | L7980-L8096 (10处) | ESP选择器低64位 |
| selector2 | 📎 IPSEC_PKT_DebugPacket | L7980-L8096 (10处) | ESP选择器高64位 |

---

## DIRECT_SINK 标注

- **无 DIRECT_SINK**：函数体内无 memcpy/strcpy/sprintf/数组下标等直接危险操作使用污点数据
- 所有污点数据均透传给外部导出函数 `IPSEC_PKT_DebugPacket` 作为调试参数

---

## 说明

1. **函数签名**：实际函数有6个参数：`lib_ctx, sa_type_desc, sadb_entry, selector1, selector2, packet_meta`
2. **污点汇聚**：所有4个污点值（selector1, selector2, dbg_mode, dbg_tag）在10处调用点全部透传给 `IPSEC_PKT_DebugPacket`
3. **外部导出函数**：`IPSEC_PKT_DebugPacket` 为外部导出函数，标记为 🟡 EXPORT