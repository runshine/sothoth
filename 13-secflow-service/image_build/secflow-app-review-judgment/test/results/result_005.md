# Unbounded recv_len from Network Pipe Controls Receive Buffer Size in SOCK_RecvMbufEx_fl

## 1. 疑点元信息
- **report_id**: result_005
- **title**: Unbounded recv_len from Network Pipe Controls Receive Buffer Size in SOCK_RecvMbufEx_fl
- **summary**: 在 `IPSEC_SOCK_ProcPipeData` 中，`recv_len` 来自外部管道消息的 msg_type 字段。但在 `IPSEC_SOCKI_HandlePipeData`（L26826）中存在有效护盾：`if (recv_len == 0 || recv_len == 2) return IPSEC_SOCKI_PipeData(...)`。该护盾将 recv_len 限制为 {0, 2}，所有其他值直接 return pipe_id，不调用任何接收函数。因此，实际攻击面已被有效阻断。此报告作为潜在风险保留，供后续代码变更时参考。
- **severity**: low
- **cvss_score**: 3.1
- **confidence**: 50
- **state**: suspected
- **category**: CWE-190 / CWE-835
- **rule_id**: DATAFLOW-DIRECT_SINK
- **rule_name**: Unbounded-Integer-Controls-Receive-Length
- **fingerprint**: IPSEC_SOCK_ProcPipeData+SOCK_RecvMbufEx_fl+recv_len+DIRECT_SINK

## 2. 上报主体 subject
- **subject.type**: source_function
- **subject.locator**: libipsec.c:L26579, L26826
- **subject.name**: IPSEC_SOCK_ProcPipeData / IPSEC_SOCKI_HandlePipeData
- **subject.version**: unknown

## 3. 数据流绑定
- **data_flow_file**: /data/files/44f9029d00650a10/app/secflow-app-dataflow-vuln-scanner/input/dataflows/dataflow/IPSEC_SOCK_ProcPipeData.md, IPSEC_SOCKI_HandlePipeData.md
- **data_flow_kind**: DIRECT_SINK
- **data_flow_source_line**: L26579 — SOCK_RecvMbufEx_fl(recv_pipe_id, recv_len, &mbuf, ...); 但 L26826 处的护盾有效限制了 recv_len ∈ {0, 2}
- **INPUT**: recv_len (unsigned int): 外部管道消息的 msg_type 字段，攻击者可控
- **传播路径**: pipe message(msg_type) → IPSEC_SOCKI_HandlePipeData → 护盾检查 → SOCK_RecvMbufEx_fl
- **sink/危险操作**: SOCK_RecvMbufEx_fl(recv_len, &mbuf, ...) — 仅当 recv_len ∈ {0, 2} 时可达

## 4. evidence.summary
护盾代码（L26826）：
```c
if (recv_len == 0 || recv_len == 2)
    return IPSEC_SOCKI_PipeData((int)pipe_id, recv_len, arg3, ctx_base, trace_target);
return pipe_id;  // ← 所有其他 recv_len 值在此返回，不调用 SOCK_RecvMbufEx_fl
```

SOCK_RecvMbufEx_fl 调用（L26579）：
```c
status = SOCK_RecvMbufEx_fl(recv_pipe_id, recv_len, &mbuf, ...);
// 实际传入的 recv_len 仅可能为 0 或 2（被护盾限制）
```

## 5. evidence.reproduction_hint
- 当前代码中 recv_len 已被有效限制，无需特殊触发条件
- 潜在风险：若未来代码移除 L26826 处的护盾，或 recv_len 的取值范围发生变化，此路径可能被利用

## 6. evidence.references
- `libipsec.c:26579` — SOCK_RecvMbufEx_fl(recv_len, &mbuf, ...)
- `libipsec.c:26826` — `if (recv_len == 0 || recv_len == 2)` 护盾
- `IPSEC_SOCK_ProcPipeData.md:dataflow` — L26579 DIRECT_SINK
- `IPSEC_SOCKI_HandlePipeData.md:dataflow` — L26826 护盾分析

## 7. 校验与绕过分析
- 护盾有效性：**护盾已生效** — `recv_len` 被限制为 {0, 2}，无法传递大值到 SOCK_RecvMbufEx_fl
- 当前状态：有效漏洞风险已被阻断，置信度 50（低）

## 8. 影响评估
- **当前风险**：低 — recv_len 已被限制，无需进一步行动
- **潜在风险**：若未来代码移除护盾，recv_len 可导致内存耗尽 DoS
- **置信度**：低

## 9. 修复建议
- 当前代码无需修复（护盾有效）
- 建议：将 L26826 的护盾逻辑显式写入文档，说明 msg_type=0/2 是唯一有效的管道数据类型

## 10. artifacts / metadata
- **artifacts**: supporting_docs/result_005_recv_len_analysis.md
- **metadata.related_issue_ids**: []
- **metadata.related_results**: []