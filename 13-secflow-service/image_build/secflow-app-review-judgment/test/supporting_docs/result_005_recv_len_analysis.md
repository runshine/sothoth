# Supporting Doc: recv_len Unbounded Buffer Size Analysis

## 1. recv_len Data Flow

```
External Pipe Message
  msg_type field (2 bytes: 0x0000 ~ 0xFFFF)
    ↓
IPSEC_SOCKI_PipeMsg (ctx, pipe_id, pipe_type, msg_type)
    ↓
IPSEC_SOCKI_HandlePipeData (pipe_id, msg_type=recv_len, pipe_type, ctx_base, target_pid)
    ↓
IPSEC_SOCKI_PipeData (pipe_id, recv_len, pipe_type, ctx_base, target_pid)
    ↓
IPSEC_SOCK_ProcPipeData (pipe_id, recv_len, arg3, ctx_base, target_pid)
    ↓
SOCK_RecvMbufEx_fl(recv_pipe_id, recv_len, &mbuf, ...)
    ← recv_len used as receive buffer size parameter
```

## 2. Source Code (libipsec.c:26563-26579)

```c
int recv_pipe_id = pipe_id;
uint8_t inbound_flag = 0;
int recv_status = 0;
int sa_type = 0;
unsigned int trace_len = 0;
// ...

// Congestion check (only for cong_node, not for recv_len)
cong_node = (int *)VOS_AVL3_Find(ctx_base + CTX_CONG_TREE_ROOT_OFF, &recv_pipe_id, ctx_base + CTX_CONG_TREE_AUX_OFF);
if (cong_node != NULL && (unsigned int)cong_node[13] > 0x3FF) {
    // Congestion path: returns early
    RETURN_GUARDED(30);
}

// recv_len is NOT checked here — directly used in SOCK_RecvMbufEx_fl
status = (int)SOCK_RecvMbufEx_fl(
    recv_pipe_id,
    recv_len,  // ← NO upper bound check
    &mbuf,
    0,
    &recv_status,
    ctx_base + CTX_RECV_CFG_OFF,
    "IPSEC_SOCK_ProcPipeData",
    148);

if (status == -1 || mbuf == 0)
    RETURN_GUARDED(25);
```

## 3. recv_len Dispatch in IPSEC_SOCKI_HandlePipeData

```c
int64_t IPSEC_SOCKI_HandlePipeData(int64_t pipe_id, unsigned int recv_len, 
                                    unsigned int arg3, int64_t ctx_base, unsigned int trace_target)
{
    if (recv_len == 0 || recv_len == 2)
        return IPSEC_SOCKI_PipeData((int)pipe_id, recv_len, arg3, ctx_base, trace_target);
    // Special handling for recv_len == 0 or 2
    // All other values bypass this check
    return pipe_id;
}
```

This function returns `pipe_id` if `recv_len` is not 0 or 2. The function at L26827:
```c
return pipe_id;
```
This is a dead code path for normal operation - `recv_len == 0 || recv_len == 2` is the normal pipe dispatch path, other values return early. But the function name suggests it's a handler for pipe data, so this early return may be intentional.

## 4. recv_len Usage in SOCK_RecvMbufEx_fl

The `SOCK_RecvMbufEx_fl` function (external library) signature:
```c
int SOCK_RecvMbufEx_fl(
    int sockfd,
    unsigned int recv_len,  // ← Tainted: controls receive buffer size
    mbuf **out_mbuf,
    int flags,
    int *recv_status,
    void *recv_cfg,
    const char *func_name,
    int line_no
);
```

Based on the dataflow report marking this as a DIRECT_SINK, `recv_len` is used as:
- Maximum receive length (if the underlying socket/pipe has no internal limit)
- Internal buffer size for mbuf allocation
- Or passed directly as-is to lower-level socket receive

## 5. Exploit Scenarios

### Scenario 1: Memory Exhaustion DoS
- Set `recv_len = 0xFFFFFFFF` (4GB receive request)
- If SOCK_RecvMbufEx_fl allocates recv_len bytes internally → 4GB memory allocation
- Multiple concurrent requests can exhaust system memory

### Scenario 2: Integer Overflow in Downstream Calculations
- If recv_len is used in subsequent calculations (e.g., subtracting from packet_len), large values may cause:
  - Integer wraparound leading to negative values
  - Unexpected behavior in protocol parsing

### Scenario 3: recv_len == 0 Bypass
- `recv_len == 0 || recv_len == 2` goes to special pipe data function
- recv_len == 0 is explicitly handled — may be intentional keepalive/ping
- recv_len == 2 is also explicitly handled — may be some control message
- All other values go to L26827's dead return path

Wait — let me re-check. Looking at L26824:
```c
if (recv_len == 0 || recv_len == 2)
    return IPSEC_SOCKI_PipeData((int)pipe_id, recv_len, arg3, ctx_base, trace_target);
return pipe_id;
```

This means:
- recv_len == 0 or 2: normal pipe data processing
- recv_len != 0 && recv_len != 2: returns pipe_id immediately (no processing)

This seems intentional — the function only processes pipe data with msg_type 0 or 2. Other msg_types are not processed at all (just returned as pipe_id). But in IPSEC_SOCK_ProcPipeData, recv_len comes from msg_type and is used in SOCK_RecvMbufEx_fl.

The vulnerability path requires:
1. msg_type != 0 && msg_type != 2 (to avoid the early return in HandlePipeData)
2. But then SOCK_RecvMbufEx_fl is called with attacker-controlled recv_len

Wait, this doesn't add up. If recv_len is neither 0 nor 2, the function returns pipe_id and SOCK_RecvMbufEx_fl is never called. Let me re-examine...

Actually, the call chain is different. IPSEC_SOCKI_HandlePipeData returns pipe_id (or calls PipeData). If it returns pipe_id (non-zero/2 case), the caller IPSEC_SOCKI_PipeMsg returns that value without calling PipeData. So the SOCK_RecvMbufEx_fl path is only reachable when recv_len == 0 or recv_len == 2.

But msg_type comes from the external pipe message, and recv_len in SOCK_RecvMbufEx_fl equals msg_type. So:
- msg_type == 0 or 2: calls IPSEC_SOCKI_PipeData → SOCK_RecvMbufEx_fl (with recv_len = 0 or 2) → normal
- msg_type != 0 && != 2: returns pipe_id without calling any receive function

This means recv_len is actually constrained to {0, 2} in the actual processing path. The DIRECT_SINK marking may be technically accurate (the code does use recv_len in SOCK_RecvMbufEx_fl for these values) but the actual attack surface is limited.

## 6. Critical Finding: Guard Effectively Mitigates recv_len Attack

**The guard at L26826 is effective!**

```c
int64_t IPSEC_SOCKI_HandlePipeData(int64_t pipe_id, unsigned int recv_len, 
                                    unsigned int arg3, int64_t ctx_base, unsigned int trace_target)
{
    if (recv_len == 0 || recv_len == 2)
        return IPSEC_SOCKI_PipeData((int)pipe_id, recv_len, arg3, ctx_base, trace_target);
    return pipe_id;  // ← For all other recv_len, returns without calling SOCK_RecvMbufEx_fl
}
```

**Analysis conclusion**: Only recv_len = 0 or 2 can reach SOCK_RecvMbufEx_fl. The actual attack surface is:
- recv_len == 0: 0-byte receive
- recv_len == 2: 2-byte receive (small control message)

Both values are within reasonable bounds for the pipe receive operation. The underlying code path is safe because of this guard.

**Result severity**: LOW — the guard provides effective mitigation. The vulnerability is noted as latent risk (should the guard be removed in future code changes).

**Note**: L26568 and L26579 are both through the same guard — both paths require recv_len ∈ {0, 2} to reach SOCK_RecvMbufEx_fl.