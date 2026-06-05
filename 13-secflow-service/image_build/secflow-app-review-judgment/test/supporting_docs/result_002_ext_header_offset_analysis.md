# Supporting Doc: IPv6 Extension Header Offset Integer Overflow Analysis

## 1. Complete Loop Context (libipsec.c:10480-10720)

```c
offset = 40;
while (1) {
    // next_header values: 44=Frag, 60=DestOpt, 0=HBH, 43=Routing, 50=ESP, 51=AH, 6=TCP/UDP
    if (next_header == 44) {
        ext_header = MBUF_MakeMemoryContinuous_fl(mbuf, offset, 8, ...);
        next_header = ext_header[0];
        offset += 8;  // Fixed, safe
    }
    else if (next_header == 51) {  // AH
        ah_header = MBUF_MakeMemoryContinuous_fl(mbuf, offset, total_len - offset, ...);
        // ...
        break;  // exits loop
    }
    else if (next_header == 50) {  // ESP
        esp_header = MBUF_MakeMemoryContinuous_fl(mbuf, offset, total_len - offset, ...);
        // ...
        break;  // exits loop
    }
    else if (next_header == 60) {  // Destination-Option
        ext_header = MBUF_MakeMemoryContinuous_fl(mbuf, offset, 2, ...);
        next_header = ext_header[0];
        offset += 8 * (ext_header[1] + 1);  // ← VULN: ext_header[1] can be 0xFF → +2048
        // falls through to check_end
    }
    else if (next_header == 0) {  // Hop-by-Hop
        ext_header = MBUF_MakeMemoryContinuous_fl(mbuf, offset, 2, ...);
        next_header = ext_header[0];
        offset += 8 * (ext_header[1] + 1);  // ← VULN
    }
    else if (next_header == 43) {  // Routing
        ext_header = MBUF_MakeMemoryContinuous_fl(mbuf, offset, 4, ...);
        next_header = ext_header[0];
        offset += 8 * (ext_header[1] + 1);  // ← VULN
    }
    else {
        goto invalid_next_header;
    }

check_end:
    if (total_packet_len <= offset)
        goto invalid_ipsec_packet;
    // loop continues with new next_header
}
```

## 2. Why the Check is Ineffective

The `total_packet_len` check `if (total_packet_len <= offset)` only compares against `total_packet_len`, which is derived from network packet fields:

```c
packet_len_field = RAW_U16(state, PST_PACKET_LEN);  // from IP header length field
total_packet_len = packet_len_field + 40;
```

An attacker can set `packet_len_field` to a large value (up to 0xFFFF), making `total_packet_len` up to 65535. If the attacker includes many extension headers, each with `ext_header[1] = 0xFF`:
- With 32 extension headers: 32 × 2048 = 65536 bytes offset
- This can exceed even `total_packet_len = 65535` (for the 32nd header)

**The real problem**: Even when `total_packet_len > offset` holds, `MBUF_MakeMemoryContinuous_fl` at subsequent iterations can be called with `offset` that exceeds the actual mbuf data boundary. The mbuf may have more data than claimed in the header (padding/misrepresentation), or the mbuf boundaries are enforced by `MBUF_MakeMemoryContinuous_fl` returning NULL when out of bounds.

However, if the mbuf happens to be physically contiguous or the attacker can pad it to be contiguous, the out-of-bounds read occurs.

## 3. Data Flow Path

```
SOCK_RecvMbufEx_fl(recv_pipe_id, recv_len, &mbuf, ...)  // mbuf from network
  → MBUF_GetControlInfo(mbuf, 10)
  → IPSEC_LIBI_HandleInputPkt / IPSEC_LIBI_HandleOutputPkt
  → IPSEC_PKT_ParseAndVerifyHdr(mbuf, ...)
  → MBUF_MakeMemoryContinuous_fl(mbuf, offset, 8, ...)  // reads ext_header from mbuf
  → ext_header[1] (from network byte at offset+1)
  → offset += 8 * (ext_header[1] + 1)  // tainted arithmetic
  → next MBUF_MakeMemoryContinuous_fl(mbuf, offset, n, ...)  // OOB access
```

## 4. Additional Notes

- `MBUF_MakeMemoryContinuous_fl` may return NULL when out of bounds, which would cause function to RETURN_GUARDED(11) at the check. However, if the mbuf data is padded/contiguous beyond claimed boundaries, the OOB access succeeds silently.
- The vulnerability requires multiple extension headers to accumulate large offset. A single extension header with ext_header[1]=0xFF only adds 2048, which may not be enough to exceed a reasonable total_packet_len.
- The actual exploitability depends on whether the attacker can make the mbuf data physically contiguous beyond the claimed boundaries. This may be difficult in practice.

## 5. Risk Boundary

- **MBUF_MakeMemoryContinuous_fl 实现未知**：若该函数对 offset 参数有边界检查并返回 NULL，则越界读取不会成功
- **需要 mbuf 填充**：攻击者需要能够让 mbuf 数据在物理上连续延伸到 offset 指定的位置
- **人工验收条件**：确认 MBUF_MakeMemoryContinuous_fl 对越界 offset 的处理行为（返回 NULL vs. 实际越界读取）