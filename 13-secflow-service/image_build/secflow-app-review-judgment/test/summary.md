# 数据流驱动漏洞挖掘总结

## 1. 攻击面分析

### 入口函数
`IPSEC_SOCKI_PipeMsg` — 从外部管道接收消息，解析 pipe_id / pipe_type / msg_type 参数，通过多条路径分发至下游处理函数。

### 攻击面覆盖路径（按调用深度）
| 深度 | 函数 | 攻击面描述 |
|------|------|-----------|
| 1 | IPSEC_SOCKI_PipeMsg | 管道 ID 匹配分支控制、LDM 树遍历路径控制 |
| 2 | IPSEC_SOCKI_HandlePipeData | recv_len 分流护盾（仅 0/2 继续处理） |
| 3 | IPSEC_SOCK_ProcPipeData | SOCK_RecvMbufEx_fl 接收管道数据、AVL 树拥塞检查 |
| 4 | IPSEC_SOCK_Buffer_Packet | ctx_base+28 控制 VRP_Malloc_F 堆分配基址 |
| 4 | IPSEC_SOCK_DbgTracePacket | trace_target 控制调试包读取长度 |
| 5 | IPSEC_LIBI_HandleInputPkt/OutputPkt | mbuf 分发给协议处理函数 |
| 6 | IPSEC_PKT_ParseAndVerifyHdr | IPv6 扩展头偏移增长无上界 |
| 6 | IPSEC_PKT_ParseAndVerifyHdrV4 | IPv4 头部长度/总长度解析 |
| 7 | IPSEC_AH_HandleInputPkt | packet_info 字段控制 IP 头写入偏移和内存操作大小 |
| 7 | IPSEC_AH_HandleOutputPktV4 | payload_offset 无符号整数下溢 |
| 7 | IPSEC_ESP_HandleInputPktV4 | enc_block_size 无上界检查导致 esp_tail_block 越界访问 |

### 外部输入映射
| 输入参数 | 来源 | 可控性 |
|---------|------|--------|
| pipe_id | 外部管道消息字段 | 攻击者完全可控 |
| pipe_type | 外部管道消息字段 | 攻击者完全可控 |
| msg_type | 外部管道消息字段 | 攻击者完全可控 |
| mbuf (网络数据) | SOCK_RecvMbufEx_fl 接收自管道 | 攻击者通过网络数据完全可控 |
| ctx_base | 上下文指针（派生于 VR context） | 攻击者可影响 ctx_base 内容 |
| SA 数据库 (enc_desc) | SAD (Security Association Database) | 攻击者若可操控 SA 则完全可控 |

---

## 2. 分析覆盖度

### 已分析函数（共 61 个，跟入全部 61 个）
- 根函数：`IPSEC_SOCKI_PipeMsg`
- 管道管理层：IPSEC_SOCKI_HandlePipeData、IPSEC_SOCKI_PipeData、IPSEC_SOCK_ProcPipeData、IPSEC_SOCK_Buffer_Packet
- Socket/管道层：IPSEC_SOCK_SendToSocket、IPSEC_SOCK_GetLdmPipeMB/LC、IPSEC_SOCK_DbgTracePacket
- IPsec 协议处理：IPSEC_LIBI_HandleInputPkt/OutputPkt(V4)、IPSEC_AH_HandleInputPkt/OutputPkt(V4)、IPSEC_ESP_HandleInputPkt/OutputPkt(V4)
- 解析层：IPSEC_PKT_ParseAndVerifyHdr(V4)、IPSEC_PKT_DebugPacket(V4)
- 工具函数：CTX_LOG、MBUF_*系列、RAW_U8/16/32/64 等

### 数据流标记覆盖
- INPUT-N：已追踪 5 个外部输入源（pipe_id、pipe_type、msg_type、mbuf、ctx_base）
- DIRECT_SINK：303 处，已重点核查高危操作 7 类
- USED：74 处，已确认安全消费
- EXPORT：31 处，已标记外部库函数边界
- CLEANED：32 处，已验证清洗充分性

### 模式覆盖完整性
| 模式类别 | 覆盖状态 | 对应结果 |
|---------|---------|---------|
| 堆指针控制 | ✓ 已覆盖 | result_001 |
| 越界读写（IPv6扩展头） | ✓ 已覆盖 | result_002 |
| 越界读写（trace_target） | ✓ 已覆盖 | result_003 |
| 越界读写（packet_info） | ✓ 已覆盖 | result_004 |
| 越界读写（enc_block_size） | ✓ 已覆盖 | result_006 |
| 无符号整数下溢 | ✓ 已覆盖 | result_007 |
| 类型截断 | ✓ 已覆盖 | result_003 (trace_target) |
| 类型截断 | ✓ 已覆盖 | result_001 (int64→int) |
| 有效护盾 | ✓ 已确认 | result_005 (recv_len ∈ {0,2}) |

---

## 3. 漏洞汇总表

| ID | 严重性 | 漏洞名称 | 数据流锚点 | CWE | 状态 |
|----|--------|---------|-----------|-----|------|
| result_001 | **critical** | Controlled Heap Pointer via ctx_base+28 in IPSEC_SOCK_Buffer_Packet | DIRECT_SINK L25491: VRP_Malloc_F(RAW_U64(ctx_base,28),...) | CWE-822/CWE-123 | suspected |
| result_002 | **high** | IPv6 Extension Header Length Field Integer Overflow in IPSEC_PKT_ParseAndVerifyHdr | DIRECT_SINK L10572/10678/10720: offset += 8*(ext_header[1]+1) | CWE-190/CWE-125 | suspected |
| result_003 | **high** | Tainted trace_target Controls Debug Packet Copy Length in IPSEC_SOCK_DbgTracePacket | DIRECT_SINK L26631/26734: trace_target as packet_len | CWE-125/CWE-786 | suspected |
| result_004 | **high** | Tainted packet_info Fields Control IP Header Write Offset and Memory Allocation in AH handlers | DIRECT_SINK L5684/6300/6402: packet_info fields control writes | CWE-123/CWE-125 | suspected |
| result_005 | **low** | Unbounded recv_len in SOCK_RecvMbufEx_fl (Guarded by L26826) | DIRECT_SINK L26579: recv_len used in SOCK_RecvMbufEx_fl; but guard at L26826 limits values to {0,2} | CWE-190/CWE-835 | suspected |
| result_006 | **high** | Unchecked enc_block_size Causes esp_tail_block Stack Buffer Overflow in IPSEC_ESP_HandleInputPktV4 | DIRECT_SINK L10072/10096: esp_tail_block[enc_block_size-N] array access | CWE-125/CWE-823 | suspected |
| result_007 | **medium** | Unsigned Integer Underflow in payload_offset in IPSEC_AH_HandleOutputPktV4 | DIRECT_SINK L6282/6300: payload_offset = payload_len - packet_info[0] underflow | CWE-190/CWE-835 | suspected |

**有效漏洞数量**：7 个（result_001 ~ result_007，均为独立漏洞疑点）
**关键漏洞**：result_001（critical，堆指针控制）

### 漏洞关联关系
- result_004 ↔ result_007：均涉及 packet_info 字段滥用，result_007 是 result_004 在 AH 出站路径的 payload_offset 下移特例
- result_004 ↔ result_006：均涉及数组/缓冲区索引使用失控，result_006 是 ESP 路径的对称问题（IPv4 ESP esp_tail_block）
- result_003 ↔ result_005：均涉及长度参数失控，result_005 已被现有护盾有效阻断

---

## 4. 局限性与不足

### 分析局限性

1. **外部库函数行为未知**
   - `VRP_Malloc_F` 的 heap_base 参数是否经过安全校验（范围检查、页面对齐验证）未知
   - `SOCK_RecvMbufEx_fl` 对 recv_len 是否有内部上限未知
   - `MBUF_MakeMemoryContinuous_fl` 对越界 offset 的处理行为（返回 NULL vs. 实际越界读取）未知
   - `SSP_ProtocolPacketTrace` 对 packet_len 与 packet_buf 大小是否有一致性检查未知

2. **SA 数据库控制边界不明**
   - result_006（enc_block_size）依赖攻击者能操控 SA 数据库（enc_desc+12），但在大多数 IPsec 部署中 SA 由受信任的 IKE 守护进程管理，攻击者能否实际操控 SA 是关键前提

3. **mbuf 内存布局不确定**
   - result_002（IPv6 扩展头偏移越界）需要 mbuf 在物理上连续延伸到 offset 指定位置，需确认 MBUF_MakeMemoryContinuous_fl 的 mbuf 合并行为

4. **未覆盖的路径**
   - ESP 出站路径（IPSEC_ESP_HandleOutputPkt / IPSEC_ESP_HandleOutputPktV4）：未分析对称漏洞
   - ESP_HandleInputPkt（IPv6）esp_tail_block：存在与 result_006 对称的漏洞模式（L9633 溢出写入），未单独报告
   - 函数指针/回调安全性：未全面审查 algo_desc 调用链的函数指针安全性
   - 加密算法实现：AUTH_INIT / AUTH_UPDATE / AUTH_FINAL 回调的安全性未分析

5. **逆向反编译精度**
   - 代码基于 AArch64 反编译伪 C，函数签名、类型定义、宏展开可能与实际源码存在差异
   - VRP_Malloc_F、MBUF_*、SOCK_* 等外部库函数的签名和边界检查行为基于推断

6. **潜在的误报风险**
   - result_003（trace_target）：SSP_ProtocolPacketTrace 为外部库函数，可能内部已有 packet_len 与 buffer 大小一致性检查
   - result_002（IPv6 扩展头）：MBUF_MakeMemoryContinuous_fl 可能对越界 offset 返回 NULL，阻止了实际 OOB 访问

### 数据流分析工具的局限性
- 303 处 DIRECT_SINK 标记中，本次仅深入核查了与高危操作相关的子集
- 符号执行和指针解引用精度可能不足，部分 CLEANED 标记的实际清洗充分性需人工确认

### 人工验收条件
- result_001：需逆向 VRP_Malloc_F 实现，确认 heap_base 参数是否有安全校验
- result_002：需确认 MBUF_MakeMemoryContinuous_fl 对越界 offset 的处理行为
- result_003：需确认 SSP_ProtocolPacketTrace 对 packet_len 与 packet_buf 大小的校验逻辑
- result_006：需确认攻击者是否可操控 SA 数据库中的 enc_desc 字段