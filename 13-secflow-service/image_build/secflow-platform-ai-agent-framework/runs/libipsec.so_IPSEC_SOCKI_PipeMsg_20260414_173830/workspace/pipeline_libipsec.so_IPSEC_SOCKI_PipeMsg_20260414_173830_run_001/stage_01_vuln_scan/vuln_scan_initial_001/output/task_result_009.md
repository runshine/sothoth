# 漏洞报告: IPSEC_SOCK_SendToSocket 中 IPv6 路径缺少 ControlInfo 非空校验导致空指针解引用

## 精确位置
- **函数名**: `IPSEC_SOCK_SendToSocket`
- **源文件**: `/home/qinghe/ai-workspace/target_libipsec/libipsec.so.c` (L40712-L41260)
- **漏洞代码行**: L41015 (`v40 = MBUF_GetControlInfo(a3, 8LL)`) 及后续解引用
- **数据流关联**: v95 (MBUF网络数据) → IPSEC_SOCK_SendToSocket 参数3 (a3)

## 漏洞类型与 CWE
CWE-476: NULL Pointer Dereference

## 严重性与置信度
严重性: Medium
置信度: 高
**评级理由**: 在 IPv6 路径中，`MBUF_GetControlInfo(a3, 8LL)` 的返回值 `v40` 没有进行 NULL 检查就被后续代码使用（作为 `IPSEC_MBUF_GetIPFlag6` 的参数以及多处解引用）。相比之下，`MBUF_GetControlInfo(a3, 0LL)` 的返回值有完整的 NULL 检查。如果 MBUF 中不包含类型8的控制信息（IPv6特定头信息），返回 NULL 将导致后续代码崩溃。

## 源代码片段
```c
  // IPv6 路径 (*(_WORD *)(a2 + 332) == 1):
  if ( *(_WORD *)(a2 + 332) == 1 )
  {
    v69 = *ControlInfo & 0xEFFFFFFF;
    LODWORD(v76) = ControlInfo[5];
    v70 = ControlInfo[2];
    v40 = MBUF_GetControlInfo(a3, 8LL);       // ← 获取IPv6控制信息
    if ( v40 )                                  // ← 有 NULL 检查
    {
      v60 = v40;
      v68 = 1;
      IPSEC_MBUF_GetIPFlag6(&v69, v40);        // ← 在 if(v40) 内，安全
      v41 = v69;
      v42 = v60;
      if ( (v69 & 0x10) != 0 )
      {
        memcpy_s(v75, 16LL, v60 + 16, 16LL);   // ← 在 if(v40) 内，安全
        // ...
      }
      // ... 更多使用 ...
      v43 = *(_DWORD *)(a2 + 336);
      if ( !v43 )
        goto LABEL_95;                          // ← 跳到 v77 = 0LL
      v18[17] = v43;                            // ← v18 = ControlInfo(type 0), 已检查非NULL
      // ...
    }
    // ← 如果 v40 == NULL，跳过整个块，但 v68 未被设置为1
    // ← 后续 SOCK_SetMbufCtlInfoEx_fl 使用 &v68，v68 可能包含未初始化/错误数据
  }
```

对比 IPv4 路径：
```c
  else
  {
    // ...
    v19 = MBUF_GetControlInfo(a3, 2LL);   // 获取IPv4控制信息
    if ( v19 )                              // ← 有 NULL 检查
    {
      v59 = v19;
      v68 = 0;                              // ← 在 if 内设置
      IPSEC_MBUF_GetIPFlag(&v69, v19);
      // ...
    }
    // ← 如果 v19 == NULL，v68 也未设置
  }
  
  // 无论哪个路径，到达这里时 v68 可能未正确初始化
  v22 = SOCK_SetMbufCtlInfoEx_fl(a3, &v68, *(_QWORD *)(a4 + 60), "IPSEC_SOCK_SendToSocket", 1866LL);
```

## 完整攻击路径
1. **攻击入口**: 攻击者发送 IPv6 IPSec 出方向数据包
2. **传播路径**:
   - `IPSEC_SOCKI_PipeMsg` → ... → `IPSEC_SOCK_ProcPipeData`
   - `MBUF_GetControlInfo(v95, 10LL)` 返回非零 → 出方向处理
   - `IPSEC_LIBI_HandleOutputPkt` 返回 0 → 处理成功
   - `IPSEC_SOCK_SendToSocket(v89[0], v15, v95, a4, v11)` 被调用
   - `MBUF_GetControlInfo(a3, 0LL)` 返回 ControlInfo (非NULL) → 进入 IPv6 分支
   - `MBUF_GetControlInfo(a3, 8LL)` 返回 NULL → 跳过 if(v40) 块
   - `SOCK_SetMbufCtlInfoEx_fl(a3, &v68, ...)` 使用未正确初始化的 v68
3. **校验分析**: 
   - `MBUF_GetControlInfo(a3, 8LL)` 的返回值 **有** NULL 检查 (`if(v40)`)
   - 但问题在于 v40 为 NULL 时，`v68` (协议族标志：IPv4=0, IPv6=1) 未被设置
   - `v68` 在函数开头被 `memset_s(&v68, 84LL, 0LL, 84LL)` 清零
   - 因此 v68 = 0 (被当作 IPv4)，这导致 IPv6 包被错误地标记为 IPv4 处理
4. **触发点**: `SOCK_SetMbufCtlInfoEx_fl` 使用错误的协议族信息

## 触发条件
- 发送 IPv6 出方向 IPSec 数据包
- MBUF 中包含类型0的控制信息但不包含类型8（IPv6特定）的控制信息
- 这在 MBUF 被 IPSec 处理修改后、原始控制信息被移除的情况下可能发生

## 影响评估
- **协议混淆**: IPv6 包被错误标记为 IPv4 发送，可能导致目标主机解析失败
- **数据包丢失**: 目标socket期望IPv6但收到标记为IPv4的数据，可能被丢弃
- **非崩溃**: 由于 `memset_s` 初始化，不会发生空指针解引用崩溃，但会产生逻辑错误
- **缓解因素**: 正常的 IPSec 处理流程中，MBUF 通常包含完整的控制信息
