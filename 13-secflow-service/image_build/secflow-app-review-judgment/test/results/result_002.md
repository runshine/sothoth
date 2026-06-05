# IPv6 Extension Header Length Field Integer Overflow Leading to Out-of-Bounds Offset

## 1. 疑点元信息
- **report_id**: result_002
- **title**: IPv6 Extension Header Length Field Integer Overflow Leading to Out-of-Bounds Offset
- **summary**: 在 `IPSEC_PKT_ParseAndVerifyHdr` 的 IPv6 扩展头解析循环中，攻击者可通过在扩展头（Destination-Option/Hop-by-Hop/Routing）的第二个字节（`ext_header[1]`）中注入任意值，控制 `offset += 8 * (ext_header[1] + 1)` 的增长步长。当 `ext_header[1]` 取最大值 0xFF 时，每次增加 2048 字节，且无上界检查，可导致 `MBUF_MakeMemoryContinuous_fl` 在越界偏移处读取数据，造成信息泄露或拒绝服务。
- **severity**: high
- **cvss_score**: 7.5
- **confidence**: 80
- **state**: suspected
- **category**: CWE-190 / CWE-125
- **rule_id**: DATAFLOW-DIRECT_SINK
- **rule_name**: Tainted-Integer-Controls-Loop-Offset
- **fingerprint**: IPSEC_PKT_ParseAndVerifyHdr+offset+ext_header+MBUF_MakeMemoryContinuous_fl+DIRECT_SINK

## 2. 上报主体 subject
- **subject.type**: source_function
- **subject.locator**: libipsec.c:L10572, L10678, L10720
- **subject.name**: IPSEC_PKT_ParseAndVerifyHdr
- **subject.version**: unknown

## 3. 数据流绑定
- **data_flow_file**: /data/files/44f9029d00650a10/app/secflow-app-dataflow-vuln-scanner/input/dataflows/dataflow/IPSEC_PKT_ParseAndVerifyHdr.md
- **data_flow_kind**: DIRECT_SINK
- **data_flow_source_line**: L10572/L10678/L10720 — `offset += 8 * (ext_header[1] + 1)` 无上界检查
- **INPUT**: mbuf (外部网络 IPv6 数据包): `SOCK_RecvMbufEx_fl` → `IPSEC_LIBI_HandleInputPkt` → `IPSEC_PKT_ParseAndVerifyHdr`
- **传播路径**: mbuf(IPv6 packet) → MBUF_MakeMemoryContinuous_fl → ext_header[1] → offset arithmetic → MBUF_MakeMemoryContinuous_fl(mbuf, offset, n)
- **sink/危险操作**: `offset += 8 * (ext_header[1] + 1)` 驱动后续 mbuf 读取偏移

## 4. evidence.summary
在 `libipsec.c` 的 `IPSEC_PKT_ParseAndVerifyHdr` 函数中，IPv6 扩展头解析循环的关键代码：

Hop-by-Hop (L10672):
```c
ext_header = MBUF_MakeMemoryContinuous_fl(mbuf, offset, 2, ...);
next_header = ext_header[0];
offset += 8 * (ext_header[1] + 1);  // ← DIRECT_SINK: ext_header[1] 无上界检查
```

Destination-Option (L10572):
```c
ext_header = MBUF_MakeMemoryContinuous_fl(mbuf, offset, 2, ...);
offset += 8 * (ext_header[1] + 1);  // ← DIRECT_SINK
```

Routing (L10720):
```c
offset += 8 * (ext_header[1] + 1);  // ← DIRECT_SINK
```

`ext_header[1]` 来自网络数据包的 IPv6 扩展头字节 1。当 `ext_header[1]=0xFF` 时，每次 offset 增加 2048。循环仅与 `total_packet_len` 比较，无绝对上界约束。

## 5. evidence.reproduction_hint
1. 构造恶意 IPv6 数据包，包含扩展头类型（Hop-by-Hop=0、Destination-Option=60、Routing=43）
2. 在扩展头的第二个字节设置大值（如 0xFF），使 offset 每次增加 2048
3. 多个扩展头连续出现，offset 快速推进到 mbuf 边界之外
4. MBUF_MakeMemoryContinuous_fl 从越界偏移读取 → OOB 读取或返回 NULL

## 6. evidence.references
- `libipsec.c:10672` — Hop-by-Hop offset += 8*(ext_header[1]+1)
- `libipsec.c:10572` — Destination-Option offset += 8*(ext_header[1]+1)
- `libipsec.c:10720` — Routing offset += 8*(ext_header[1]+1)
- `IPSEC_PKT_ParseAndVerifyHdr.md:dataflow` — L10572/L10705/L10720 DIRECT_SINK

## 7. 校验与绕过分析
- 已检查：函数有 `total_packet_len > 0x28` 初始检查和 `total_packet_len <= offset` 退出条件
- 绕过原因：`total_packet_len` 来自网络包头字段，可设为大值；offset 仅与 total_packet_len 比较，无绝对上限
- 攻击者可通过多个扩展头（每个 +2048）累积推进 offset，使其超出实际 mbuf 数据边界

## 8. 影响评估
- **越界读取**：MBUF_MakeMemoryContinuous_fl 在 mbuf 越界偏移处读取，可能暴露内核内存
- **信息泄露**：越界读取的数据被解析处理，可能暴露敏感内存内容
- **拒绝服务**：越界访问可能触发页面错误，导致进程崩溃

## 9. 修复建议
1. 对 `ext_header[1]` 添加上界检查：`if (ext_header[1] > 0xFE) return ERROR;`
2. 在 offset 增量后添加上界检查：`if (offset > total_packet_len) return ERROR;`
3. 限制 offset 增量在剩余数据包长度范围内

## 10. artifacts / metadata
- **artifacts**: supporting_docs/result_002_ext_header_offset_analysis.md
- **metadata.related_issue_ids**: []
- **metadata.related_results**: []