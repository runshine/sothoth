# Supporting Doc: trace_target → trace_buf Length Mismatch Analysis

## 1. Complete Data Flow Path

```
pipe_id (attacker-controlled)
  → target_pid = RAW_U32((void *)ctx_base, 140/196/1256) or pipe_id
  → IPSEC_SOCKI_HandlePipeData(pipe_id, msg_type, pipe_type, ctx_base, target_pid)
  → IPSEC_SOCKI_PipeData(pipe_id, msg_type, pipe_type, ctx_base, target_pid)
  → IPSEC_SOCK_ProcPipeData(pipe_id, msg_type, arg3, ctx_base, target_pid)
      [L26597] IPSEC_SOCK_CopyDbgTracePacket(ctx_base, vr_entry, mbuf, &trace_len, &trace_buf)
                // trace_buf allocated by CopyDbgTracePacket based on mbuf content
                // trace_len derived from mbuf, NOT from target_pid
      [L26631] IPSEC_SOCK_DbgTracePacket(ctx_base, trace_cfg, trace_buf, &trace_info0, trace_target)
                // trace_target from target_pid (attacker-controlled)
                // Used as packet_len parameter in SSP_ProtocolPacketTrace
```

## 2. trace_buf vs. trace_target Size Relationship

### trace_buf Allocation
```c
// L26597 in IPSEC_SOCK_ProcPipeData:
IPSEC_SOCK_CopyDbgTracePacket(ctx_base, vr_entry, mbuf, &trace_len, (uint64_t *)&trace_buf);
// trace_len and trace_buf are produced by IPSEC_SOCK_CopyDbgTracePacket
// trace_buf size is related to mbuf data content, NOT trace_target
```

From dataflow report:
- trace_len 🔴 TAINTED — copy length is controlled by mbuf content
- trace_buf 🔴 TAINTED — allocated by CopyDbgTracePacket, size from mbuf

### trace_target Origin
```c
// L26881 in IPSEC_SOCKI_PipeMsg:
target_pid = (unsigned int)pipe_id;

// L26837 (PP4 branch):
target_pid = RAW_U32((void *)ctx_base, 196);  // from ctx_base

// L26839 (LDM MB branch):
target_pid = RAW_U32((void *)ctx_base, 1256);  // from ctx_base
```

target_pid can be:
- The raw pipe_id value (attacker-controlled unsigned int)
- A value extracted from ctx_base (controlled by ctx_base content)

## 3. Size Mismatch Vulnerability

In `IPSEC_SOCK_DbgTracePacket` (L23590):
```c
int64_t IPSEC_SOCK_DbgTracePacket(int64_t ctx_base, int64_t trace_cfg_base, 
                                   int64_t packet_buf, int64_t trace_info_base, 
                                   unsigned int packet_len)  // ← trace_target
{
    IpsecSockTraceRecord trace_record = {0, 0, 0};
    // ...
    trace_record.word0 = ((uint64_t)packet_len << 32) | RAW_U32((void *)ctx_base, 4);
    // ...
    SSP_ProtocolPacketTrace(trace_handle, &trace_record, 
        RAW_U32((void *)trace_info_base, 4), packet_buf);  // ← packet_buf is trace_buf
    // SSP_ProtocolPacketTrace will use packet_len (trace_target) to read from packet_buf (trace_buf)
}
```

**Mismatch**: `trace_target` (from target_pid, attacker-controlled) vs. `trace_buf` size (from mbuf content).

Example scenario:
- mbuf contains small packet → trace_buf allocated for small buffer (e.g., 64 bytes)
- target_pid = 0xFFFFFFFF → trace_target = 0xFFFFFFFF
- SSP_ProtocolPacketTrace reads 0xFFFFFFFF bytes from trace_buf (64-byte buffer) → OOB read

## 4. Prerequisites and Attack Complexity

1. Debug mode must be enabled (dbg_enable != 0) — guarded by debug flag checks
2. The function must reach the DbgTracePacket call path
3. trace_target must be larger than trace_buf size
4. The OOB data must flow somewhere that causes observable impact

**Risk**: SSP_ProtocolPacketTrace is an external library function, analysis scope ended. Impact depends on how it processes the buffer.