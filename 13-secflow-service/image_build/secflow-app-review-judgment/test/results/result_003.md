# Tainted trace_target Controls Debug Packet Copy Length Leading to Buffer Over-Read

## 1. 疑点元信息
- **report_id**: result_003
- **title**: Tainted trace_target Controls Debug Packet Copy Length Leading to Buffer Over-Read
- **summary**: 在 `IPSEC_SOCK_ProcPipeData` 中，攻击者通过外部管道消息控制 `trace_target` 参数（派生于 `target_pid`），该参数通过 `IPSEC_SOCK_DbgTracePacket` 直接进入 `SSP_ProtocolPacketTrace`，作为 `packet_len` 用于从 `trace_buf` 读取数据。`trace_buf` 由 `IPSEC_SOCK_CopyDbgTracePacket` 分配，大小由 mbuf 内容决定，与 `trace_target` 无关联，存在 `trace_target > trace_buf_size` 导致越界读取的风险。
- **severity**: high
- **cvss_score**: 6.5
- **confidence**: 65
- **state**: suspected
- **category**: CWE-125 / CWE-786
- **rule_id**: DATAFLOW-DIRECT_SINK
- **rule_name**: Tainted-Length-Controls-Debug-Buffer-Copy
- **fingerprint**: IPSEC_SOCK_ProcPipeData+trace_target+SSP_ProtocolPacketTrace+packet_len+DIRECT_SINK

## 2. 上报主体 subject
- **subject.type**: source_function
- **subject.locator**: libipsec.c:L26631, L26734
- **subject.name**: IPSEC_SOCK_ProcPipeData
- **subject.version**: unknown

## 3. 数据流绑定
- **data_flow_file**: /data/files/44f9029d00650a10/app/secflow-app-dataflow-vuln-scanner/input/dataflows/dataflow/IPSEC_SOCK_ProcPipeData.md
- **data_flow_kind**: DIRECT_SINK
- **data_flow_source_line**: L26631/L26734 — trace_target 作为 packet_len 传入
- **INPUT**: target_pid (unsigned int): 派生于 pipe_id 和 ctx_base，攻击者可通过控制原始 pipe_id 操纵最终取值
- **传播路径**: pipe_id → target_pid → IPSEC_SOCKI_HandlePipeData → IPSEC_SOCK_ProcPipeData → trace_target → IPSEC_SOCK_DbgTracePacket → SSP_ProtocolPacketTrace
- **sink/危险操作**: `SSP_ProtocolPacketTrace(..., packet_buf)` — packet_len 控制读取长度

## 4. evidence.summary
关键代码链：

**L26597**:
```c
IPSEC_SOCK_CopyDbgTracePacket(ctx_base, vr_entry, mbuf, &trace_len, &trace_buf);
// trace_buf 大小由 mbuf 内容决定，与 trace_target 无关联
```

**L26631**:
```c
RAW_U32(&trace_info0, 4) = trace_len;
RAW_U8(&trace_info0, 0) = 2;
IPSEC_SOCK_DbgTracePacket(ctx_base, trace_cfg, trace_buf, &trace_info0, trace_target);
// trace_target (attacker-controlled) 传入作为 packet_len
```

**L23590** (DbgTracePacket):
```c
trace_record.word0 = ((uint64_t)packet_len << 32) | RAW_U32((void *)ctx_base, 4);
SSP_ProtocolPacketTrace(trace_handle, &trace_record, ..., packet_buf);
// 若 packet_len > trace_buf 实际大小 → OOB 读取
```

`trace_target` 来自 `target_pid`（AVL 树查找结果），攻击者可通过控制原始 pipe_id 和 AVL 树内容来影响最终取值。

## 5. evidence.reproduction_hint
1. 攻击者控制管道消息使 `target_pid` 传为较大值（如 0xFFFFFFFF）
2. 构造 mbuf 令 `trace_buf` 大小受限（如仅 64 字节）
3. `SSP_ProtocolPacketTrace` 用 packet_len=0xFFFFFFFF 从 trace_buf(64B) 读取 → OOB 读取

## 6. evidence.references
- `libipsec.c:26631` — outbound: DbgTracePacket with trace_target
- `libipsec.c:26734` — inbound: 同上
- `libipsec.c:23590` — trace_record.word0 = ((uint64_t)packet_len << 32) | ...
- `IPSEC_SOCK_ProcPipeData.md:dataflow` — L26631/L26734 DIRECT_SINK

## 7. 校验与绕过分析
- 已检查：`dbg_enable` 检查和 `RAW_U32(trace_cfg, 64)` 序列号检查
- 绕过原因：`trace_target` 来自 ctx_base 偏移 196/1256/8 或 pipe_id，攻击者可通过预先在 AVL 树中插入特定值来控制
- `trace_buf` 大小与 `trace_target` 无关联，两者未做一致性检查

## 8. 影响评估
- **越界读取**：SSP_ProtocolPacketTrace 从 trace_buf 读取超过其实际大小的数据
- **信息泄露**：读取的数据被传递到调试子系统，可能暴露敏感内存内容
- **置信度**：中等 — 取决于 SSP_ProtocolPacketTrace 是否检查 packet_len 与 buffer 大小

## 9. 修复建议
1. 在调用 DbgTracePacket 前对 `trace_target` 做上界检查：`trace_target = min(trace_target, trace_len)`
2. 或在 SSP_ProtocolPacketTrace 内部校验 packet_len 与 packet_buf 大小
3. `trace_buf` 分配时使用 `max(trace_len, trace_target)` 作为分配大小

## 10. artifacts / metadata
- **artifacts**: supporting_docs/result_003_trace_target_analysis.md
- **metadata.related_issue_ids**: []
- **metadata.related_results**: []