# 漏洞报告: IPSEC_SOCK_SendToPP6orPP4orLDMPipe 中 MBUF_GetControlInfo 返回 NULL 时 MBUF 未释放导致内存泄露

## 精确位置
- **函数名**: `IPSEC_SOCK_SendToPP6orPP4orLDMPipe` (offset 0x4E820)
- **源文件**: `/home/qinghe/ai-workspace/target_libipsec/libipsec.so.c` L41262-L41660
- **漏洞代码行**: L41582 (`return result;` 其中 result = 19, MBUF 未释放)
- **调用者泄露点**: `IPSEC_SOCK_ProcPipeData` L44325 (`++*(_DWORD *)(a4 + 1232); return v55;`)
- **数据流关联**: v95 (MBUF, 来自 SOCK_RecvMbufEx_fl) → SendToPP6orPP4orLDMPipe 参数1 (a1) → MBUF_GetControlInfo(a1, 0) → NULL → return 19

## 漏洞类型与 CWE
CWE-401: Missing Release of Memory after Effective Lifetime (MBUF 内存泄露)

## 严重性与置信度
严重性: Medium
置信度: 高
**评级理由**: 代码路径明确可追踪。`IPSEC_SOCK_SendToPP6orPP4orLDMPipe` 在 `MBUF_GetControlInfo(a1, 0)` 返回 NULL 时，设置 `result = 19` 并跳过 LABEL_14（token 分配和发送），直接 `return result`，未调用 `MBUF_Destroy_fl`。调用者 `IPSEC_SOCK_ProcPipeData` 在收到非零、非拥塞(575410306)的返回值时，仅递增计数器后直接返回，也未释放 v95 (MBUF)。此漏洞与已确认的 result_007 属于同一类别（MBUF 泄露），但位于完全不同的错误路径上。

## 源代码片段

**IPSEC_SOCK_SendToPP6orPP4orLDMPipe 内部** (offset 0x4F1A0 附近):
```c
    // SA 跟踪ID存在 (v12 = *(a3+336) != 0) 时进入此路径
    v23 = *(_DWORD *)(a3 + 344);
    v45 = *(_DWORD *)(a3 + 336);
    v43 = v12;
    v44 = v23;
    v42 = v23;
    ControlInfo = (_DWORD *)MBUF_GetControlInfo(a1, 0LL);  // ← 获取 MBUF 基础控制信息
    result = 19LL;                                           // ← 预设错误码
    if ( ControlInfo )
    {
      ControlInfo[17] = *(_DWORD *)(a3 + 336);  // 写入跟踪信息
      ControlInfo[15] = *(_DWORD *)(a3 + 344);
      ControlInfo[18] = *(_DWORD *)(a2 + 4);
      // ... 调试跟踪 ...
LABEL_14:
      v13 = MBUF_TokenAlloc_fl(v10, a1, *(_QWORD *)(a2 + 60), ...);  // 正常发送路径
      // ...
    }
    // ★ 如果 ControlInfo == NULL，跳过 if 块，直接到达:
  }
  return result;   // ← 返回 19，a1 (MBUF) 未被销毁！
```

**调用者 IPSEC_SOCK_ProcPipeData** (offset 0x533xx 附近):
```c
      v55 = IPSEC_SOCK_SendToPP6orPP4orLDMPipe(v95, a4, v28, v11, LdmPipeLC, v53);
      if ( !v55 )
        return 0LL;                              // 成功：MBUF 已发送
      v56 = *(_BYTE *)(a4 + 392);
      if ( v55 == 575410306 )
      {
        // 拥塞路径：正确销毁 MBUF
        ++*(_DWORD *)(a4 + 1232);
        MBUF_Destroy_fl(v95, "IPSEC_SOCK_ProcPipeData", 287LL);
        return 575410306LL;
      }
      else
      {
        // ★ 其他错误路径（包括 v55=19）：未销毁 MBUF!
        // ... 日志 ...
        ++*(_DWORD *)(a4 + 1232);
        return v55;   // ← v95 (MBUF) 泄露！
      }
```

## 完整攻击路径
1. **攻击入口**: 网络攻击者发送 IPSec 数据包到达 IPSec 管道
2. **传播路径**:
   - `IPSEC_SOCKI_PipeMsg` → `IPSEC_SOCKI_HandlePipeData` → `IPSEC_SOCKI_PipeData` (重试循环)
   - → `IPSEC_SOCK_ProcPipeData`: `SOCK_RecvMbufEx_fl` 接收 MBUF (v95)
   - 入方向处理: `IPSEC_LIBI_HandleInputPkt(v14, v95, ...)` 成功返回 0
   - 非拥塞路径: `MBUF_GetControlInfo(v95, 9)` 获取通用包信息 v52 (成功)
   - → `IPSEC_SOCK_SendToPP6orPP4orLDMPipe(v95, a4, v28, v11, LdmPipeLC, v53)`
   - 函数内: `*(a3+336)` (SA 跟踪 ID) 非零 → 进入跟踪信息写入路径
   - `MBUF_GetControlInfo(a1, 0)` 返回 NULL → `result = 19`，跳过发送逻辑
   - 返回 19 给调用者，MBUF 未释放
   - 调用者: `v55 = 19` (非零，非拥塞) → 进入 else 分支 → `return 19`，v95 泄露
3. **校验分析**: 
   - 拥塞路径 (v55 == 575410306) 正确释放了 MBUF ✅
   - 管道无效 (v10 == -1) 时 SendToPP6 内部释放 ✅
   - 管道未就绪 (状态检查) 时 SendToPP6 内部释放 ✅
   - Token 分配失败时 SendToPP6 内部释放 ✅
   - **但 ControlInfo NULL 路径 (return 19)：两层函数均未释放 ❌**
4. **触发点**: `return v55;` in ProcPipeData — MBUF 引用丢失，永久泄露

## 触发条件
- 入方向 IPSec 数据包被 `HandleInputPkt` 成功处理（返回 0）
- VS 节点中 SA 跟踪 ID `*(v28+336)` 非零（调试跟踪已启用）
- `MBUF_GetControlInfo(v95, 0)` 返回 NULL（MBUF 基础控制信息不存在）
  - 这可能在 IPSec 入方向处理（ESP 解密/AH 验证）修改了 MBUF 结构后发生
  - 或在 MBUF 元数据损坏的极端情况下发生

## 影响评估
- **MBUF 池耗尽 DoS**: 每次触发泄露一个 MBUF 结构（含网络数据包的全部内存）。VRP 系统的 MBUF 池是预分配的有限资源，持续泄露将导致所有网络通信中断。
- **与 result_007 的关系**: 同属 CWE-401 MBUF 泄露，但触发路径完全不同。result_007 在 `SOCK_RecvMbufEx_fl` 异常返回时触发，本漏洞在 `SendToPP6orPP4orLDMPipe` 内部 ControlInfo 获取失败时触发。
- **缓解措施**: MBUF 池耗尽后系统可能自动重启/恢复，但在此期间服务完全中断。
