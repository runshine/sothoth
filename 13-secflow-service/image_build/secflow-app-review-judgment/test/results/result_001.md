# Controlled Heap Pointer via Tainted ctx_base+28 in IPSEC_SOCK_Buffer_Packet

## 1. 疑点元信息
- **report_id**: result_001
- **title**: Controlled Heap Pointer via Tainted ctx_base+28 in IPSEC_SOCK_Buffer_Packet
- **summary**: 在 `IPSEC_SOCK_Buffer_Packet` 中，攻击者可通过外部管道输入控制 `ctx_base`，进而控制 `ctx_base+28` 处的 64 位值。该值被直接用作 `VRP_Malloc_F` 的第一个参数（堆分配基址），可导致内存分配重定向到任意地址。攻击者若能将分配重定向到可控内存区域并写入结构化数据（list_node），可破坏堆管理结构，造成堆损坏或代码执行。
- **severity**: critical
- **cvss_score**: 9.1
- **confidence**: 70
- **state**: suspected
- **category**: CWE-822 / CWE-123
- **rule_id**: DATAFLOW-DIRECT_SINK
- **rule_name**: Controlled-Pointer-Arithmetic-as-Heap-Parameter
- **fingerprint**: IPSEC_SOCK_Buffer_Packet+VRP_Malloc_F+ctx_base+28+DIRECT_SINK

## 2. 上报主体 subject
- **subject.type**: source_function
- **subject.locator**: libipsec.c:L25491
- **subject.name**: IPSEC_SOCK_Buffer_Packet
- **subject.version**: unknown

## 3. 数据流绑定
- **data_flow_file**: /data/files/44f9029d00650a10/app/secflow-app-dataflow-vuln-scanner/input/dataflows/dataflow/IPSEC_SOCK_Buffer_Packet.md
- **data_flow_kind**: DIRECT_SINK
- **data_flow_source_line**: L25491: `VRP_Malloc_F(RAW_U64((void *)ctx_base, 28), ...)` — 污点指针运算结果作为堆分配基址参数
- **INPUT**: INPUT-1 (ctx_base): 外部管道参数，`IPSEC_SOCKI_PipeMsg` → `IPSEC_SOCKI_HandlePipeData` → `IPSEC_SOCKI_PipeData` → `IPSEC_SOCK_ProcPipeData` → `IPSEC_SOCK_Buffer_Packet` 层层传递，攻击者完全可控
- **传播路径**: pipe_id(msg_type) → target_pid → IPSEC_SOCKI_HandlePipeData → IPSEC_SOCKI_PipeData → IPSEC_SOCK_ProcPipeData → IPSEC_SOCK_Buffer_Packet → ctx_base → RAW_U64(ctx_base,28) → VRP_Malloc_F heap pointer
- **sink/危险操作**: `VRP_Malloc_F(RAW_U64((void *)ctx_base, 28), ...)` — 第1参数被污染为堆分配基址

## 4. evidence.summary
在 `libipsec.c` 的 `IPSEC_SOCK_Buffer_Packet` 函数（L25491）中，`ctx_base` 由外部管道消息（通过 `pipe_id`/`target_pid` 链路）传入，直接从 `ctx_base+28` 读取 64 位值作为堆分配基址传入 `VRP_Malloc_F`。

关键代码（L25491）：
```c
list_node = (uint64_t *)VRP_Malloc_F(RAW_U64((void *)ctx_base, 28), g_aucVrpMemPt, 16, IPSEC_SOCK_PIPE_C, 2682);
if (list_node == NULL)
    return 2;

list_node[0] = 0;
list_node[1] = (uint64_t)mbuf;
if (RAW_U64(cong_node, 36) != 0) {
    **(uint64_t **)(cong_node + 11) = (uint64_t)list_node;
    RAW_U64(cong_node, 44) = (uint64_t)list_node;
    packet_count = cong_node[13] + 1;
    cong_node[13] = packet_count;
} else {
    packet_count = cong_node[13] + 1;
    RAW_U64(cong_node, 36) = (uint64_t)list_node;
    RAW_U64(cong_node, 44) = (uint64_t)list_node;
    cong_node[13] = packet_count;
}
```
若攻击者控制 `ctx_base+28` 的值，可将堆分配重定向到任意地址。若该地址在映射内存区域中，后续 `list_node[0/1]` 的写入操作将写入攻击者指定的地址，从而可能破坏堆元数据或相邻内存结构。

调用链：攻击者发送管道消息 → `IPSEC_SOCKI_PipeMsg` 解析 pipe_id/msg_type/target_pid → 传入 `IPSEC_SOCKI_HandlePipeData` → 传入 `IPSEC_SOCKI_PipeData` → 传入 `IPSEC_SOCK_ProcPipeData` → 传入 `IPSEC_SOCK_Buffer_Packet` → 传入 ctx_base

## 5. evidence.reproduction_hint
1. 攻击者向 IPSEC 模块发送管道消息，设置 pipe_id 使 `IPSEC_SOCK_ProcPipeData` 执行到 `outbound_send` 分支
2. 在 VR entry 中注入特定上下文，使得 ctx_base+28 处保存指向攻击者可控区域的指针值
3. `VRP_Malloc_F` 将从攻击者指定的基址开始分配 16 字节
4. 后续 `list_node[0/1]` 写入操作将破坏目标区域数据结构

## 6. evidence.references
- `libipsec.c:25491` — VRP_Malloc_F 第1参数为污染指针
- `libipsec.c:25493-25496` — list_node[0/1] 写入操作
- `libipsec.c:26835` — ctx_base 从 IPSEC_SOCKI_PipeMsg 管道消息参数传入
- `IPSEC_SOCK_Buffer_Packet.md:dataflow` — L25491 DIRECT_SINK 标记
- `IPSEC_SOCK_ProcPipeData.md:dataflow` — L26660 调用 IPSEC_SOCK_Buffer_Packet

## 7. 校验与绕过分析
- 已检查：函数入口仅有 `if ((unsigned int)cong_node[13] > 0x400)` 拥塞树节点包数检查，无 ctx_base 值校验
- 绕过或失效原因：`ctx_base` 由外部管道消息参数直接传入（来自 `pipe_id/target_pid` 链路），中间无清洗。VRP_Malloc_F 的第一个参数（heap_base）未经任何范围或有效性检查
- 需验证：VRP_Malloc_F 内部实现是否对 heap_base 参数做了安全校验

## 8. 影响评估
- **堆分配重定向**：攻击者控制 ctx_base+28 值，可将 `VRP_Malloc_F` 的堆分配重定向到任意地址
- **堆元数据破坏**：`list_node[0/1]` 的写入操作将写入攻击者指定地址，若该区域包含堆管理元数据，可能触发堆损坏
- **潜在代码执行**：若攻击者能在目标地址预先写入结构化的伪造 list_node 数据，可进一步控制函数指针或关键数据结构
- **置信度**：中等 — VRP_Malloc_F 的实现未在分析范围内，需确认是否对 heap_base 参数做了安全校验

## 9. 修复建议
1. `ctx_base+28` 的值在作为堆分配基址前，应与已知有效的堆地址范围进行比较校验
2. 考虑使用 ctx_base 的固定字段（如 ctx_base+8 已知用于其他函数分配）而非 ctx_base+28
3. 建议在 VRP_Malloc_F 内部对 heap_base 参数进行范围合法性检查

## 10. artifacts / metadata
- **artifacts**: supporting_docs/result_001_ctx_base28_analysis.md
- **metadata.related_issue_ids**: []
- **metadata.related_results**: []