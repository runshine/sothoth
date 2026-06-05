# Supporting Doc: AH packet_info Field Analysis

## 1. packet_info Array Field Map

The `packet_info[]` array is filled by `IPSEC_PKT_ParseAndVerifyHdr` from mbuf header fields:

| Index | Value Source | Usage |
|-------|-------------|-------|
| packet_info[0] | IP header length (IHL × 4) | IP header size, MBUF read size |
| packet_info[1] | AH header offset | RAW_U8 write offset |
| packet_info[4] | Total packet length | Payload length calculation |
| packet_info[5] | Derived | Payload copy length |
| packet_info[6] | Derived | Payload + overhead length |
| packet_info[9-12] | Flow selector fields | Auth context setup |
| packet_info[14] | Debug flags | Debug logging |

## 2. Key Vulnerability Code (AH_HandleInputPkt)

```c
// L5687: IP header extraction with tainted packet_info[0]
ip_header = MBUF_MakeMemoryContinuous_fl(mbuf_base, 0, packet_info[0], ...);
// packet_info[0] controls read size from mbuf

// L5698: AH header extraction
ah_header = MBUF_MakeMemoryContinuous_fl(mbuf_base, packet_info[0], packet_info[4] - packet_info[0], ...);
// packet_info[4] - packet_info[0] controls AH header read size

// L5714: SA lookup key from AH header
sa_lookup_key = __builtin_bswap32(*(uint32_t *)(ah_header + 4));  // SPI from network

// L5849-5860: Auth hash length check
auth_hash_len + 4 != 4 * ah_header[1]
// Only checks format, not absolute bounds on packet_info values

// L5881: Payload copy length calculation
payload_copy_len = packet_info[4] - (auth_hash_len + 12 + packet_info[0]);
packet_info[5] = payload_copy_len;
packet_info[6] = payload_copy_len;

// L5900: Payload copy allocation (VRP_Malloc_F)
payload_copy = VRP_Malloc_F(..., payload_copy_len, ...);  // tainted size

// L5931-5939: Payload chunk loop
while (payload_copy_len != 0 && copied_len < payload_copy_len) {
    int64_t chunk_base;
    chunk_len = payload_copy_len - copied_len;
    if (chunk_len > 0x800) chunk_len = 2048;  // ← Soft cap: 2048
    chunk_base = MBUF_MakeMemoryContinuous_fl(mbuf_base, copy_offset, chunk_len, ...);
    // ...
    memcpy_s((uint8_t *)payload_copy + copied_len, chunk_len, chunk_base, chunk_len);  // L5980
    copied_len += chunk_len;
    copy_offset += chunk_len;
}
```

## 3. Integer Underflow Scenario

If `packet_info[4] < packet_info[0] + auth_hash_len + 12`:
- `payload_copy_len` becomes a large unsigned int (integer underflow from subtraction)
- `VRP_Malloc_F` is called with huge allocation size → memory exhaustion DoS
- Or `chunk_len = 0xFFFFFFFF - copied_len + 2048` in loop → potential issues

## 4. RAW_U8 Write Offset Analysis

In AH_HandleInputPkt (L5840):
```c
if ((RAW_U32((void *)sa_entry, 72) & 0x2000) != 0) {
    // Tunnel mode flag
    int next_header = ah_header[0];
    if (next_header == 41 || next_header == 4) {
        // Tunnel mode error...
    }
    // Writing to IP header at offset packet_info[1]
    // This is OUTBOUND path write, for IPv6 input it's different
}
```

In IPSEC_ESP_HandleInputPkt (L9683):
```c
if (packet_info[1] != 0) {
    unsigned int prev_next_header = *((uint8_t *)packet_info + 9);
    if (prev_next_header != 60 && prev_next_header != 0 && ...) {
        RAW_U8((void *)ip_header, packet_info[1]) = esp_tail_block[enc_block_size - 1];
    } else {
        RAW_U8((void *)ip_header, packet_info[1]) = next_header;
    }
}
```

The `packet_info[1]` write offset in ESP_HandleInputPkt uses a different calculation path but has the same pattern: write to ip_header at offset `packet_info[1]` where `packet_info[1]` comes from mbuf header parsing.

## 5. Risk Boundary

- `VRP_Malloc_F` with huge size: May fail gracefully (return NULL), causing DoS rather than code execution
- `memcpy_s` chunk_len cap: The `if (chunk_len > 0x800) chunk_len = 2048` provides a soft cap, reducing but not eliminating overflow risk
- RAW_U8 write to ip_header: If ip_header is a valid mbuf-backed buffer, writing at offset packet_info[1] may corrupt mbuf data structure
- Need to check: Does MBUF_MakeMemoryContinuous_fl return a separate buffer or a view into mbuf? If separate, RAW_U8 writes may not affect mbuf