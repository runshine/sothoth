# Supporting Doc: esp_tail_block Buffer Overflow Analysis

## 1. Stack Buffer esp_tail_block Declaration

### IPv6 ESP Handler (IPSEC_ESP_HandleInputPkt)
```c
// libipsec.c:9357
uint8_t esp_tail_block[16] = {0};
```

### IPv4 ESP Handler (IPSEC_ESP_HandleInputPktV4)
```c
// libipsec.c:9791
uint8_t esp_tail_block[16] = {0};
```

## 2. enc_block_size Source and Control

### enc_block_size derivation (both IPv4 and IPv6):
```c
// IPv4: libipsec.c:9896
enc_desc = RAW_U64((void *)sa_entry, 8);
enc_block_size = RAW_U16((void *)enc_desc, 12);

// IPv6: libipsec.c:9469
enc_desc = RAW_U64((void *)sa_entry, 8);
enc_block_size = RAW_U16((void *)enc_desc, 12);
```

### Attack vector:
- `sa_entry` is found via `VOS_AVL3_Find` using SPI from packet header
- `enc_desc` points to the encryption algorithm descriptor stored in the SA entry
- If attacker can influence the SA database (e.g., via SA negotiation or SA injection), they can set enc_block_size to a malicious value

## 3. Validation Check Analysis (IPv6 vs IPv4)

### IPv6 (ESP_HandleInputPkt)
```c
// L9501: Checks payload_len >= SA_IV + packet_info[0] + auth_hash_len
if ((unsigned int)(RAW_U16((void *)sa_entry, 28) + *packet_info + auth_hash_len) + 8 >= packet_len) {
    RETURN_GUARDED(15);
}

// L9504-9508: Derives payload_len and checks alignment
payload_len = packet_len - 8 - (RAW_U16((void *)sa_entry, 28) + *packet_info + auth_hash_len);
if (((enc_block_size - 1) & payload_len) != 0) {
    RETURN_GUARDED(15);
}

// L9633: MBUF_CopyDataFromMBufToBuffer copies enc_block_size bytes
if (RAW_U32((void *)enc_desc, 0) == 0) {
    MBUF_CopyDataFromMBufToBuffer(mbuf, packet_len - enc_block_size - auth_hash_len, 
                                  enc_block_size, esp_tail_block);  // ← OOB if enc_block_size > 16
    // No enc_block_size upper bound check before copy!
} else {
    // Decryption path
}

// L9669: esp_tail_block access
pad_length = esp_tail_block[enc_block_size - 2];  // ← OOB if enc_block_size >= 18
```

### IPv4 (ESP_HandleInputPktV4)
```c
// L10048: Same payload length check, same weakness
if ((unsigned int)(RAW_U16((void *)sa_entry, 28) + *packet_info + auth_hash_len) + 8 >= packet_len) {
    RETURN_GUARDED(15);
}

// L10055: Alignment check can be bypassed
// enc_block_size=17: (16 & payload_len) != 0 — passes if payload_len is even
// enc_block_size=18: (17 & payload_len) != 0 — passes if payload_len is odd

// L10072: MBUF_CopyDataFromMBufToBuffer(..., enc_block_size, esp_tail_block)
// Same OOB copy vulnerability

// L10096-10097: esp_tail_block access
pad_index = enc_block_size - 2;
pad_length = esp_tail_block[pad_index];  // ← OOB if enc_block_size >= 18
```

## 4. Attack Scenario (IPv4)

1. Attacker creates a custom SA with enc_desc pointing to memory where `RAW_U16(enc_desc, 12) = 18`
2. Attacker sends IPv4 ESP packet with SPI matching the custom SA
3. SA lookup finds attacker's SA, enc_block_size = 18
4. For enc_desc[0] == 0 path: 18-byte copy to 16-byte buffer → stack overflow write
5. For enc_desc[0] != 0 path: esp_tail_block[16] read → stack OOB read

## 5. Similar Pattern: IPv6 ESP Handler

The same esp_tail_block pattern exists in IPSEC_ESP_HandleInputPkt (IPv6):
- esp_tail_block[16] declared at line 9357
- MBUF_CopyDataFromMBufToBuffer(..., enc_block_size, esp_tail_block) at line 9633
- esp_tail_block[enc_block_size-2] at line 9669
- Same enc_block_size check weakness applies

## 6. Risk Boundary

- **SA database control requirement**: This vulnerability requires ability to manipulate SA entries in the SAD
- In many IPSec deployments, SA entries are managed by a trusted key management daemon (IKE daemon)
- However, if the system allows dynamic SA creation from network traffic, or if there are SA injection vulnerabilities, this becomes exploitable
- **Recommendation**: Even if SA control is trusted, enc_block_size should be bounded (e.g., 8-16 for common ciphers) to prevent coding errors from causing buffer overflows