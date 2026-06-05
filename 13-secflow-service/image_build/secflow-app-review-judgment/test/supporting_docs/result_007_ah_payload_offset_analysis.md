# Supporting Doc: payload_offset Unsigned Integer Underflow Analysis

## 1. Complete Vulnerability Chain

### Source (IPSEC_PKT_ParseAndVerifyHdrV4):
```c
// libipsec.c:11218
header_len = 4 * (version_nibble & 0xF);  // Attacker controls version_nibble low nibble → header_len ∈ [20, 60]

// Line 11227-11228
total_data_len = MBUF_GetTotalDataLength(mbuf);  // Attacker controls via IP header
RAW_U32(state, PST_TOTAL_LEN) = (uint32_t)total_data_len;
```

### Propagation (IPSEC_AH_HandleOutputPktV4):
```c
// libipsec.c:6281
payload_len = packet_info[4];  // = total_data_len from IP header field

// libipsec.c:6282 — VULNERABILITY: Unsigned integer subtraction
payload_offset = payload_len - packet_info[0];  // packet_info[0] = header_len (20-60)
```

### Sink (VRP_Malloc_F):
```c
// libipsec.c:6300
payload_copy = VRP_Malloc_F(
    RAW_U64((void *)lib_ctx_base, 8),
    g_aucVrpMemPt,
    payload_offset,  // ← Underflowed value used as allocation size
    IPSEC_LIB_AH_C,
    1021);
```

## 2. Concrete Attack Example

### IPv4 Header Fields (20-byte minimum IPv4 header):
```
Byte 0: Version=4, IHL=15 → ip_header[0] = 0x4F
Byte 0 low nibble: 0xF → header_len = 60 (MAX)
Bytes 2-3 (Total Length): 0x0030 → 48 bytes (MIN valid IPv4 packet)
```

### Calculation:
```
packet_info[0] = header_len = 60
packet_info[4] = total_data_len = 48
payload_len = 48
payload_offset = 48 - 60 = (uint64_t)(-12) = 0xFFFFFFFFFFFFFFF4

VRP_Malloc_F(..., 0xFFFFFFFFFFFFFFF4, ...) → ~16 exabyte allocation
```

### Also: Loop DoS
```c
// libipsec.c:6319
while (payload_offset != 0 && copied_len < payload_offset) {
    // Loop ~0xFFFFFFFFFFFFFFF4 / 2048 = 0x7FFFFFFFFFFFFFF5 iterations!
    // Even with chunk_len cap at 2048, this causes CPU exhaustion
}
```

## 3. Check Bypass Analysis

### The Check at L6286-6292:
```c
packet_size_with_ah = payload_len + auth_hash_len + 12;
if (packet_size_with_ah > 0xFFFFu) {
    RETURN_GUARDED(15);
}
```

**Why this check doesn't catch the attack:**
- `payload_len = 48`, `auth_hash_len = 12` (for SHA1), `packet_size_with_ah = 48 + 12 + 12 = 72`
- `72 < 0xFFFF` → check passes!
- The check only validates the total packet size, not the relationship between `payload_len` and `packet_info[0]`

### Missing Check:
```c
// What should be there:
if (payload_len < packet_info[0]) {  // Underflow condition
    IPSEC_LIB_LOG_IF_ENABLED(..., "Invalid payload offset: payload_len < header length");
    RETURN_GUARDED(15);
}
```

## 4. Symmetric Path: AH_HandleInputPkt (IPv6)

### IPSEC_AH_HandleInputPkt (IPv6):
```c
// libipsec.c:5881
payload_copy_len = packet_info[4] - (auth_hash_len + 12 + packet_info[0]);
packet_info[5] = payload_copy_len;
packet_info[6] = payload_copy_len;

// libipsec.c:5900
payload_copy = VRP_Malloc_F(..., payload_copy_len, ...);  // Same underflow risk
```

**Same vulnerability**: `payload_copy_len = packet_info[4] - (auth_hash_len + 12 + packet_info[0])`
If `packet_info[4] < auth_hash_len + 12 + packet_info[0]`, this underflows.

However, in IPv6 path, there are some additional checks during AH header parsing that may mitigate:
- Line 5834: `auth_hash_len + 4 == 4 * ah_header[1]` — authenticator length check
- This check only validates AH header format, not relative sizes

**Conclusion**: The same vulnerability exists in the IPv6 path, but the conditions are slightly different.

## 5. Risk Boundary

- **IPv4 AH outbound processing**: mbuf comes from `SOCK_RecvMbufEx_fl` via pipe
- **Attacker needs to send outbound traffic**: This may require being on the local network or having access to the IPsec socket
- **VRP_Malloc_F behavior**: Large allocations typically fail (return NULL) or trigger OOM killer, causing DoS rather than code execution
- **Loop DoS**: Even if allocation fails, the unsigned comparison `payload_offset != 0` in the loop is always true, potentially causing CPU exhaustion before NULL check