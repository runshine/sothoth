# Supporting Doc: ctx_base+28 Controlled Heap Pointer Analysis

## 1. Function Call Graph (Full Path)

```
IPSEC_SOCKI_PipeMsg(ctx, pipe_id, pipe_type, msg_type)
  └── IPSEC_SOCKI_HandlePipeData(pipe_id, msg_type, pipe_type, ctx_base, target_pid)
        └── IPSEC_SOCKI_PipeData((int)pipe_id, msg_type, pipe_type, ctx_base, target_pid)
              └── IPSEC_SOCK_ProcPipeData(pipe_id, msg_type, arg3, ctx_base, target_pid)
                    └── IPSEC_SOCK_Buffer_Packet(cong_node, mbuf, ctx_base)
                          └── VRP_Malloc_F(RAW_U64((void *)ctx_base, 28), ...)  ← VULN
```

## 2. Source Code Evidence

### VULNERABLE CODE (libipsec.c:25491)
```c
int64_t IPSEC_SOCK_Buffer_Packet(int *cong_node, int64_t mbuf, int64_t ctx_base)
{
    uint64_t *list_node;
    int packet_count;

    if ((unsigned int)cong_node[13] > 0x400)
        VRP_Assert(IPSEC_SOCK_PIPE_C, 2680, 0);

    list_node = (uint64_t *)VRP_Malloc_F(
        RAW_U64((void *)ctx_base, 28),  // ← Attacker can control ctx_base+28
        g_aucVrpMemPt,
        16,
        IPSEC_SOCK_PIPE_C,
        2682);

    if (list_node == NULL)
        return 2;

    list_node[0] = 0;
    list_node[1] = (uint64_t)mbuf;  // ← Writes to attacker-controlled address
    if (RAW_U64(cong_node, 36) != 0) {
        **(uint64_t **)(cong_node + 11) = (uint64_t)list_node;  // ← Double dereference
        RAW_U64(cong_node, 44) = (uint64_t)list_node;
        packet_count = cong_node[13] + 1;
        cong_node[13] = packet_count;
    } else {
        packet_count = cong_node[13] + 1;
        RAW_U64(cong_node, 36) = (uint64_t)list_node;
        RAW_U64(cong_node, 44) = (uint64_t)list_node;
        cong_node[13] = packet_count;
    }
    // ...
}
```

### ctx_base Origin (libipsec.c:26835)
```c
int64_t IPSEC_SOCKI_HandlePipeData(int64_t pipe_id, unsigned int recv_len,
                                   unsigned int arg3, int64_t ctx_base, unsigned int trace_target)
{
    if (recv_len == 0 || recv_len == 2)
        return IPSEC_SOCKI_PipeData((int)pipe_id, recv_len, arg3, ctx_base, trace_target);
    return pipe_id;
}
```

### Root Function (libipsec.c:26842)
```c
int64_t IPSEC_SOCKI_PipeMsg(int64_t pipe_id, unsigned int pipe_type, unsigned int msg_type, int64_t ctx_base)
{
    // ctx_base from external source
    // pipe_id from external pipe message
    // target_pid derived from ctx_base or pipe_id AVL lookup
    return IPSEC_SOCKI_HandlePipeData(pipe_id, msg_type, pipe_type, ctx_base, target_pid);
}
```

## 3. Attack Surface Analysis

### Attacker Control Points:
1. **pipe_id**: 外部管道消息字段，可控（经 `IPSEC_SOCKI_PipeMsg` 入口）
2. **msg_type**: 外部管道消息字段，可控
3. **ctx_base**: 外部传入的上下文指针，通常来自 VR context，但通过不同消息路径可影响其值
4. **ctx_base+28**: 最终攻击目标 — 从 ctx_base 偏移 28 处读取的 64 位值

### Attack Prerequisites:
- 攻击者需要能够向 IPSEC 模块发送管道消息
- 攻击者需要能够操控 VR context 或 ctx_base 的内容，使 ctx_base+28 处的值为攻击者可控地址
- 攻击者需要触发 `outbound_send` 分支（拥塞树中有 cong_node）

### VRP_Malloc_F Call Signature (推断):
```c
void *VRP_Malloc_F(
    uint64_t heap_base,    // ← First param: attacker-controlled!
    char *mem_pool_name,   // Memory pool identifier
    size_t alloc_size,     // Fixed: 16 bytes
    int comp_id,           // Component identifier
    int line_no            // Line number for debugging
);
```

## 4. Risk Boundary

- **VRP_Malloc_F 实现未知**：若 VRP_Malloc_F 对 heap_base 参数做了有效性检查（如范围检查、页面对齐检查），则此漏洞的严重性降低
- **建议**：需查看 VRP_Malloc_F 的实现以确认是否有安全校验
- **人工验收条件**：逆向或查看 VRP_Malloc_F (或底层 malloc wrapper) 的实现，确认 heap_base 参数是否经过安全校验