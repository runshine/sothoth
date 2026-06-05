# Tainted packet_info Fields Control IP Header Write Offset and AH Payload Copy Size

## 1. 疑点元信息
- **report_id**: result_004
- **title**: Tainted packet_info Fields Control IP Header Write Offset and AH Payload Copy Size
- **summary**: 在 `IPSEC_AH_HandleInputPkt` 和 `IPSEC_AH_HandleOutputPktV4` 中，`packet_info[0/1/4]` 字段全部来自解析后的 mbuf 数据（IP 头字段），攻击者可注入任意值：packet_info[1] 控制 IP 头写入偏移，packet_info[0/4] 控制 VRP_Malloc_F 分配大小和 memcpy_s 拷贝大小。这些值驱动内存操作的大小和偏移参数，缺乏严格的上界校验，可能导致 IP 头越界写入、分配大小失控或整数下溢。
- **severity**: high
- **cvss_score**: 7.1
- **confidence**: 75
- **state**: suspected
- **category**: CWE-123 / CWE-125
- **rule_id**: DATAFLOW-DIRECT_SINK
- **rule_name**: Tainted-Length-Fields-Control-Memory-Operations
- **fingerprint**: IPSEC_AH_HandleInputPkt+packet_info+memcpy_s+VRP_Malloc_F+DIRECT_SINK

## 2. 上报主体 subject
- **subject.type**: source_function
- **subject.locator**: libipsec.c:L5684, L5710, L5980 (AH_HandleInputPkt), L6300, L6402, L6432 (AH_HandleOutputPktV4)
- **subject.name**: IPSEC_AH_HandleInputPkt / IPSEC_AH_HandleOutputPktV4
- **subject.version**: unknown

## 3. 数据流绑定
- **data_flow_file**: /data/files/44f9029d00650a10/app/secflow-app-dataflow-vuln-scanner/input/dataflows/dataflow/IPSEC_AH_HandleInputPkt.md, IPSEC_AH_HandleOutputPktV4.md
- **data_flow_kind**: DIRECT_SINK
- **data_flow_source_line**: 
  - L5684: `RAW_U8((void*)ip_header, packet_info[1]) = ah_header[0]` — 污染偏移写入
  - L5710: `MBUF_MakeMemoryContinuous_fl(mbuf, packet_info[0], packet_info[4]-packet_info[0], ...)` — 污染大小控制读取
  - L5980: `memcpy_s(payload_cursor, chunk_len, chunk_base, chunk_len)` — chunk_len 由污染值控制
  - L6300: `VRP_Malloc_F(..., payload_offset, ...)` — payload_offset 由污染值控制
  - L6402: `VRP_Malloc_F(..., packet_info[0], ...)` — 污染大小控制分配
  - L6432: `MBUF_CopyDataFromMBufToBuffer(..., packet_info[0], ...)` — 污染大小控制拷贝
- **INPUT**: mbuf (外部网络 IPv6/IPv4 数据包): SOCK_RecvMbufEx_fl → ... → IPSEC_AH_HandleInputPkt / IPSEC_AH_HandleOutputPktV4
- **传播路径**: mbuf → IPSEC_PKT_ParseAndVerifyHdr/HdrV4 → packet_info[] → 直接驱动各内存操作的大小/偏移参数
- **sink/危险操作**: VRP_Malloc_F/memcpy_s/MBUF_MakeMemoryContinuous_fl — 大小/偏移由网络数据驱动

## 4. evidence.summary
### AH_HandleInputPkt (IPv6):
```c
// L5687: packet_info[0] 控制 IP 头读取大小
ip_header = MBUF_MakeMemoryContinuous_fl(mbuf_base, 0, packet_info[0], ...);
// L5698: packet_info[4]-packet_info[0] 控制 AH 头读取大小
ah_header = MBUF_MakeMemoryContinuous_fl(mbuf_base, packet_info[0], packet_info[4]-packet_info[0], ...);
// L5684: packet_info[1] 作为写入偏移
RAW_U8((void *)ip_header, packet_info[1]) = ah_header[0];  // ← 污染偏移写入 IP 头
// L5881: payload_copy_len = packet_info[4] - (auth_hash_len+12+packet_info[0]) 无下溢检查
// L5900: VRP_Malloc_F(..., payload_copy_len, ...) 分配大小由网络数据控制
// L5980: memcpy_s(payload_cursor, chunk_len, chunk_base, chunk_len) — chunk_len 由污染值控制
```

### AH_HandleOutputPktV4 (IPv4):
```c
// L6281: payload_len = packet_info[4] (网络数据驱动)
// L6282: payload_offset = payload_len - packet_info[0] — 无符号整数下溢
packet_info[5] = payload_offset;  // 下溢值写入 packet_info
// L6300: VRP_Malloc_F(..., payload_offset, ...) — 下溢值作为分配大小
payload_copy = VRP_Malloc_F(..., payload_offset, ...);
// L6402: VRP_Malloc_F(..., packet_info[0], ...) — packet_info[0] 控制分配大小
// L6432: MBUF_CopyDataFromMBufToBuffer(..., packet_info[0], ...) — 污染大小控制拷贝
```

## 5. evidence.reproduction_hint
1. 攻击者构造 IPv6 AH 入站数据包，IP 头部长度字段（packet_info[0]）设为 0，使 IP 头读取越界
2. 攻击者设置 packet_info[1] 为异常大值，使 RAW_U8 写入 IP 头越界
3. 攻击者在 AH_HandleOutputPktV4 中设置 IHL 最大(60)但 total_len 很小，使 payload_offset 下溢

## 6. evidence.references
- `libipsec.c:5684` — RAW_U8((void*)ip_header, packet_info[1]) = ah_header[0]
- `libipsec.c:5710` — MBUF_MakeMemoryContinuous_fl(mbuf, packet_info[0], packet_info[4]-packet_info[0], ...)
- `libipsec.c:5980` — memcpy_s(payload_cursor, chunk_len, chunk_base, chunk_len)
- `libipsec.c:6300` — VRP_Malloc_F(..., payload_offset, ...)
- `libipsec.c:6402` — VRP_Malloc_F(..., packet_info[0], ...)
- `IPSEC_AH_HandleInputPkt.md:dataflow` — L5684/L5719 DIRECT_SINK
- `IPSEC_AH_HandleOutputPktV4.md:dataflow` — L6300/L6402/L6432 DIRECT_SINK

## 7. 校验与绕过分析
- 已检查：仅 `auth_hash_len + 4 == 4 * ah_header[1]` 验证 AH 头格式，不限制 packet_info 各字段绝对大小
- 绕过原因：packet_info 字段来自 IP 头解析，无独立上界检查。packet_info[1] 可设为任意值，packet_info[4]<packet_info[0] 可导致 payload_offset 下溢

## 8. 影响评估
- **IP 头越界写入**：packet_info[1] 控制写入偏移，异常大值导致越界写入
- **分配大小失控**：payload_offset 由 packet_info[4]-packet_info[0] 计算，下溢后传入 VRP_Malloc_F
- **整数下溢**：packet_info[4] < packet_info[0] 导致 payload_offset 变成 ~16 exabytes

## 9. 修复建议
1. 对 packet_info[1] 添加上界检查：`if (packet_info[1] >= packet_info[0]) return ERROR;`
2. 对 packet_info[4] 添加合理性检查：`if (packet_info[4] <= packet_info[0]) return ERROR;`
3. 在计算 payload_offset 前检查是否发生整数下溢

## 10. artifacts / metadata
- **artifacts**: supporting_docs/result_004_ah_packet_info_analysis.md
- **metadata.related_issue_ids**: []
- **metadata.related_results**: [result_007 (related: payload_offset underflow)]