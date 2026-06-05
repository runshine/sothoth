# Unchecked enc_block_size Causes Stack Buffer Overflow via esp_tail_block Array Access in IPSEC_ESP_HandleInputPktV4

## 1. 疑点元信息
- **report_id**: result_006
- **title**: Unchecked enc_block_size Causes Stack Buffer Overflow via esp_tail_block Array Access
- **summary**: 在 `IPSEC_ESP_HandleInputPktV4` 中，`enc_block_size` 从 SA 条目的加密描述符 `enc_desc+12` 读取，未经上界检查即用于索引 16 字节的栈缓冲区 `esp_tail_block[16]`。当 `enc_block_size >= 18` 时，数组访问 `esp_tail_block[enc_block_size-2/3]` 越界读取；若 SA 的 `enc_desc[0]==0`（非加密路径），`MBUF_CopyDataFromMBufToBuffer(..., enc_block_size, esp_tail_block)` 将 `enc_block_size` 字节复制到 16 字节缓冲区，造成栈溢出写入。攻击者若能操控 SA 数据库，可触发堆元数据破坏或栈数据泄露。
- **severity**: high
- **cvss_score**: 7.5
- **confidence**: 75
- **state**: suspected
- **category**: CWE-125 / CWE-823
- **rule_id**: DATAFLOW-DIRECT_SINK
- **rule_name**: Tainted-Index-Exceeds-Stack-Buffer-Size
- **fingerprint**: IPSEC_ESP_HandleInputPktV4+enc_block_size+esp_tail_block+OOB-READ-WRITE

## 2. 上报主体 subject
- **subject.type**: source_function
- **subject.locator**: libipsec.c:L10096, L10105, L10072
- **subject.name**: IPSEC_ESP_HandleInputPktV4
- **subject.version**: unknown

## 3. 数据流绑定
- **data_flow_file**: /data/files/44f9029d00650a10/app/secflow-app-dataflow-vuln-scanner/input/dataflows/dataflow/IPSEC_ESP_HandleInputPktV4.md
- **data_flow_kind**: DIRECT_SINK
- **data_flow_source_line**: 
  - L10072: `MBUF_CopyDataFromMBufToBuffer(mbuf, ..., enc_block_size, esp_tail_block)` — 溢出写入
  - L10096: `pad_length = esp_tail_block[pad_index]` — pad_index = enc_block_size-2，无上界检查
  - L10105: `esp_tail_block[enc_block_size - 3]` — 越界读取
- **INPUT**: mbuf (外部 IPv4 ESP 数据包): SOCK_RecvMbufEx_fl → ... → IPSEC_ESP_HandleInputPktV4
- **传播路径**: mbuf(IPv4 ESP) → SPI → SA查找(enc_desc) → enc_block_size → esp_tail_block索引
- **sink/危险操作**: esp_tail_block[enc_block_size-2/3] 数组访问 / MBUF_CopyDataFromMBufToBuffer 写入

## 4. evidence.summary
**L9791: 16字节栈缓冲区**
```c
uint8_t esp_tail_block[16] = {0};
```

**L9896: enc_block_size 从 SA 数据库读取（无上界检查）**
```c
enc_desc = RAW_U64((void *)sa_entry, 8);
enc_block_size = RAW_U16((void *)enc_desc, 12);
// ↑ 来自 SA 数据库，若攻击者可操控 SAD → enc_block_size 可控
```

**L10055: 对齐检查可被绕过**
```c
if (((enc_block_size - 1) & payload_len) != 0) {
    RETURN_GUARDED(15);
}
// enc_block_size=17: (16 & payload_len) != 0 → 若 payload_len 偶数，检查通过
// enc_block_size=18: (17 & payload_len) != 0 → 若 payload_len 奇数，检查通过
```

**L10072: 栈溢出写入（当 enc_desc[0]==0 时）**
```c
if (RAW_U32((void *)enc_desc, 0) == 0) {
    MBUF_CopyDataFromMBufToBuffer(mbuf, packet_len - enc_block_size - auth_hash_len,
                                   enc_block_size, esp_tail_block);
    // ↑ 若 enc_block_size=18，18字节复制到16字节 esp_tail_block → 栈溢出
}
```

**L10096-10097: 越界读取**
```c
pad_index = enc_block_size - 2;  // enc_block_size=18 → pad_index=16 → 越界
pad_length = esp_tail_block[pad_index];  // ← OOB 读取
next_protocol = esp_tail_block[pad_index + 1];  // ← OOB 读取
```

**L10105: 第二处越界读取**
```c
if (pad_length != 0 && esp_tail_block[enc_block_size - 3] != (uint8_t)pad_length) {
// enc_block_size=18 → esp_tail_block[15] → 最后有效字节，但 enc_block_size-3=15 是有效访问
// enc_block_size=19 → esp_tail_block[16] → OOB
```

## 5. evidence.reproduction_hint
1. 攻击者操控 SA 数据库，使 `enc_desc+12` 处值为 18+
2. 构造 IPv4 ESP 数据包，使用该 SA
3. 若 enc_desc[0]==0：`MBUF_CopyDataFromMBufToBuffer` 将 18 字节复制到 16 字节 esp_tail_block → 栈溢出
4. 否则：`esp_tail_block[16]` 读取 → 栈数据泄露或 esp_tail_block[17] 读取 → SIGSEGV

## 6. evidence.references
- `libipsec.c:9791` — `uint8_t esp_tail_block[16] = {0}` 栈缓冲区
- `libipsec.c:9896` — `enc_block_size = RAW_U16(enc_desc, 12)` 来自 SA
- `libipsec.c:10055` — 对齐检查可被 enc_block_size=17/18 绕过
- `libipsec.c:10072` — MBUF_CopyDataFromMBufToBuffer(..., enc_block_size, esp_tail_block) 溢出
- `libipsec.c:10096` — `esp_tail_block[pad_index]` 越界读取
- `libipsec.c:10105` — `esp_tail_block[enc_block_size-3]` 越界读取

## 7. 校验与绕过分析
- 已检查：仅有 payload length 对齐检查（L10055），对 enc_block_size 无效
- 绕过原因：`enc_block_size` 来自 SA 数据库（enc_desc+12），若攻击者可控制 SA 条目，可直接设置为 18+
- enc_desc[0]==0 路径（直接复制无加密）触发栈溢出；enc_desc[0]!=0 路径（解密）触发越界读取

## 8. 影响评估
- **栈溢出写入**：`esp_tail_block` 是栈局部变量，越界写入可破坏返回地址或相邻栈数据
- **栈越界读取**：可能暴露栈上的敏感数据（返回地址、函数指针等）
- **崩溃**：`esp_tail_block[17+]` 访问超出栈边界，触发 SIGSEGV
- **置信度**：中高 — 需确认攻击者是否可操控 SA 条目

## 9. 修复建议
1. 对 `enc_block_size` 添加上界检查：`if (enc_block_size > 16 || enc_block_size < 2) { RETURN_GUARDED; }`
2. 在 MBUF_CopyDataFromMBufToBuffer 调用前，检查 `enc_block_size <= 16`
3. 考虑将 `esp_tail_block` 从栈分配改为固定最大尺寸堆分配

## 10. artifacts / metadata
- **artifacts**: supporting_docs/result_006_esp_tail_block_overflow.md
- **metadata.related_issue_ids**: []
- **metadata.related_results**: [result_004 (symmetric IPv6 issue)]