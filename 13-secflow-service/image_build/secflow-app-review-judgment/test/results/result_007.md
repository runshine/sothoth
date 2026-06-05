# Unsigned Integer Underflow in payload_offset Enables Massive Heap Allocation DoS in IPSEC_AH_HandleOutputPktV4

## 1. 疑点元信息
- **report_id**: result_007
- **title**: Unsigned Integer Underflow in payload_offset Enables Massive Heap Allocation DoS
- **summary**: 在 `IPSEC_AH_HandleOutputPktV4` 中，`payload_offset = payload_len - packet_info[0]` 执行无符号整数减法，当攻击者控制的 `packet_info[0]`（IP 头部长度，最大60）大于 `payload_len`（总长度字段）时，`payload_offset` 发生无符号整数下溢，变成约 0xFFFFFFF0+ 的极大值，然后传入 `VRP_Malloc_F` 作为分配大小，导致内存耗尽 DoS 或分配失败；后续循环的 `while (payload_offset != 0 && copied_len < payload_offset)` 也可能造成 CPU 耗尽。
- **severity**: medium
- **cvss_score**: 5.1
- **confidence**: 80
- **state**: suspected
- **category**: CWE-190 / CWE-835
- **rule_id**: DATAFLOW-DIRECT_SINK
- **rule_name**: Unsigned-Integer-Underflow-Controls-Allocation-Size
- **fingerprint**: IPSEC_AH_HandleOutputPktV4+payload_offset+VRP_Malloc_F+unsigned-underflow

## 2. 上报主体 subject
- **subject.type**: source_function
- **subject.locator**: libipsec.c:L6282, L6300, L6319
- **subject.name**: IPSEC_AH_HandleOutputPktV4
- **subject.version**: unknown

## 3. 数据流绑定
- **data_flow_file**: /data/files/44f9029d00650a10/app/secflow-app-dataflow-vuln-scanner/input/dataflows/dataflow/IPSEC_AH_HandleOutputPktV4.md
- **data_flow_kind**: DIRECT_SINK
- **data_flow_source_line**: 
  - L6282: `payload_offset = payload_len - packet_info[0]` — 无符号减法下溢
  - L6300: `VRP_Malloc_F(..., payload_offset, ...)` — 下溢值作为分配大小
  - L6319: `while (payload_offset != 0 && copied_len < payload_offset)` — 下溢值驱动循环边界
- **INPUT**: mbuf (外部 IPv4 AH 数据包): 从网络接收 → IPSEC_AH_HandleOutputPktV4
- **传播路径**: mbuf(IPv4 AH packet) → IPSEC_PKT_ParseAndVerifyHdrV4 → packet_info[0/4] → payload_offset 计算 → VRP_Malloc_F
- **sink/危险操作**: VRP_Malloc_F(..., payload_offset, ...) — 下溢值作为分配大小

## 4. evidence.summary
**L6281-6284: payload_offset 计算（下溢点）**
```c
payload_len = packet_info[4];  // 来自 IP 头总长度字段，可控
payload_offset = payload_len - packet_info[0];  // ← 无符号整数下溢
packet_info[5] = payload_offset;  // 下溢值写入 packet_info[5]
packet_info[6] = payload_offset + 12;
```

**L6286-6292: 唯一的尺寸检查（不充分）**
```c
packet_size_with_ah = payload_len + auth_hash_len + 12;
if (packet_size_with_ah > 0xFFFFu) {
    RETURN_GUARDED(status);
}
// 仅检查总大小，不检查 payload_offset 本身
// 若 payload_len=48, auth_hash_len=12 → packet_size_with_ah=72 → 检查通过
```

**L6300: 危险分配**
```c
payload_copy = VRP_Malloc_F(
    RAW_U64((void *)lib_ctx_base, 8), g_aucVrpMemPt,
    payload_offset,  // ← 可能是 ~16 exabytes 的下溢值
    IPSEC_LIB_AH_C, 1021);
```

**L6319: 危险循环**
```c
while (payload_offset != 0 && copied_len < payload_offset) {
    // 下溢后 payload_offset != 0 恒为真，循环约 0xFFFFFFFFFFFFFFF4 / 2048 次
    // 即便分配失败 NULL，循环在 NULL 检查前已执行大量迭代 → CPU 耗尽
}
```

**示例**：payload_len=48, packet_info[0]=60 → payload_offset=48-60=0xFFFFFFFFFFFFFFF4

## 5. evidence.reproduction_hint
1. 攻击者构造 IPv4 AH 出站数据包，IHL=15（packet_info[0]=60），总长度字段=48（payload_len 小）
2. `payload_offset = 48 - 60 = ~16 exabytes`
3. `VRP_Malloc_F` 尝试分配巨大内存 → OOM killer 或分配失败
4. 即使 VRP_Malloc_F 返回 NULL，循环 `while (payload_offset != 0)` 仍执行大量迭代 → CPU 耗尽

## 6. evidence.references
- `libipsec.c:6281` — `payload_len = packet_info[4]` 来自 IP 头
- `libipsec.c:6282` — `payload_offset = payload_len - packet_info[0]` 无符号下溢
- `libipsec.c:6300` — `VRP_Malloc_F(..., payload_offset, ...)` 危险分配
- `libipsec.c:6319` — `while (payload_offset != 0 && copied_len < payload_offset)` CPU 耗尽
- `IPSEC_AH_HandleOutputPktV4.md:dataflow` — L6300 DIRECT_SINK

## 7. 校验与绕过分析
- 已检查：`packet_size_with_ah > 0xFFFFu` 不检查 payload_offset 本身
- 绕过原因：IHL 最大60 + 总长度字段小值 = 可导致 payload_len < packet_info[0]
- 攻击者可通过 IP 头字段组合（IHL=max, total_len=min）使 payload_len < packet_info[0]

## 8. 影响评估
- **内存耗尽 DoS**：VRP_Malloc_F 尝试分配 ~16 exabytes，多个并发请求快速耗尽系统内存
- **CPU 耗尽**：即使分配失败，下溢循环在 NULL 检查前已执行大量迭代
- **服务中断**：分配失败导致 IPsec AH 处理中断
- **置信度**：高 — unsigned 减法下溢是确定性行为

## 9. 修复建议
1. 在计算 payload_offset 前添加下溢检查：`if (payload_len < packet_info[0]) { RETURN_GUARDED(ERROR); }`
2. 对 payload_offset 添加上界检查：`if (payload_offset > MAX_PAYLOAD_OFFSET) { RETURN_GUARDED(ERROR); }`
3. 在 VRP_Malloc_F 调用前，检查分配大小是否在合理范围内

## 10. artifacts / metadata
- **artifacts**: supporting_docs/result_007_ah_payload_offset_analysis.md
- **metadata.related_issue_ids**: []
- **metadata.related_results**: [result_004 (related: packet_info field misuse)]