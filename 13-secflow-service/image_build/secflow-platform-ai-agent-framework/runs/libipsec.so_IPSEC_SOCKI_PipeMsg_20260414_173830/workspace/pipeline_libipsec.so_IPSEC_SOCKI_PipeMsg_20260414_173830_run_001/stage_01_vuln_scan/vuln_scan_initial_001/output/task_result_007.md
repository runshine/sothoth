# 漏洞报告: IPSEC_SOCK_ProcPipeData 中 v95 (MBUF) 在错误路径未销毁导致内存泄露

## 精确位置
- **函数名**: `IPSEC_SOCK_ProcPipeData`
- **源文件**: `/home/qinghe/ai-workspace/target_libipsec/libipsec.so.c` (L43657-L44650)
- **漏洞代码行**: L43832 (`if (v10 != -3840) { VRP_Assert(...); return v10; }`)
- **数据流关联**: 网络数据 MBUF (v95) 从 SOCK_RecvMbufEx_fl 获取

## 漏洞类型与 CWE
CWE-401: Missing Release of Memory after Effective Lifetime (内存泄露)

## 严重性与置信度
严重性: Medium
置信度: 高
**评级理由**: 在 `SOCK_RecvMbufEx_fl` 返回值既不是 -1 也不是 -3840 的错误路径上，函数触发 `VRP_Assert` 后直接 `return v10`，但此时 `v95` (MBUF指针) 已经被成功接收（非NULL），却没有调用 `MBUF_Destroy_fl(v95, ...)` 进行释放。这导致每次遇到该错误条件时泄露一个 MBUF 数据结构。

## 源代码片段
```c
  // L43829: 接收网络数据
  v10 = SOCK_RecvMbufEx_fl(v89[0], a2, &v95, 0LL, &v91, a4 + 968, "IPSEC_SOCK_ProcPipeData", 148LL);
  
  // L43830: 接收失败检查 — v95 为 NULL，无需释放
  if ( v10 == -1 || !v95 )
    return 25LL;                     // OK: v95 为 NULL
  
  // L43832: 非预期返回值检查
  if ( v10 != -3840 )                // -3840 = 0xFFFFF100 = 正常接收
  {
    VRP_Assert("/usr1/ipsec/ipsec_v8/src/ipsec/ipsec_sock_pipe.c", 153LL, 0LL);
    return v10;                      // ← BUG: v95 已非NULL但未释放！
  }
  
  // ... 正常处理路径（v10 == -3840）...
  // 在所有正常和错误路径结束时都有 MBUF_Destroy_fl(v95, ...) 调用
```

对比其他错误路径的正确处理：
```c
  // VS未找到路径:
  if ( !v11 )
  {
    // ... 日志 ...
    MBUF_Destroy_fl(v95, "IPSEC_SOCK_ProcPipeData", 168LL);  // ← 正确释放
    return 7LL;
  }
  
  // 入方向处理失败路径:
  if ( v29 )
  {
    // ... 日志 ...
    MBUF_Destroy_fl(v95, "IPSEC_SOCK_ProcPipeData", 223LL);  // ← 正确释放
    return v29;
  }
```

## 完整攻击路径
1. **攻击入口**: 通过管道发送数据触发 `SOCK_RecvMbufEx_fl` 调用
2. **传播路径**:
   - `IPSEC_SOCKI_PipeMsg` → `HandlePipeData` → `PipeData`（10次重试）→ `ProcPipeData`
   - `SOCK_RecvMbufEx_fl` 返回非 {-1, -3840} 的值（如其他错误码）
   - v95 已被设置为有效的 MBUF 指针
   - 函数直接返回 v10，v95 对应的 MBUF 内存永不释放
3. **校验分析**: 
   - `v10 == -1` 检查在前，此时 v95 可能为 NULL，return 25 安全
   - `!v95` 检查紧随其后，确保后续 v95 非 NULL
   - 但 `v10 != -3840` 时，虽然 v95 非 NULL，没有调用 `MBUF_Destroy_fl`
4. **触发点**: `return v10;` — 丢失 MBUF 引用

## 触发条件
- `SOCK_RecvMbufEx_fl` 需要返回非 -1 且非 -3840 的值
- 同时 v95 被设置为非 NULL
- 这可能在底层socket异常、协议错误、资源不足等条件下发生
- `IPSEC_SOCKI_PipeData` 的重试循环中，每次重试触发一次泄露

## 影响评估
- **内存泄露**: 每次触发泄露一个 MBUF 结构（包含网络数据包的全部内存）
- **DoS潜力**: 如果攻击者能持续触发该条件（结合10次重试循环），可以快速耗尽 MBUF 池
- **MBUF池大小有限**: 网络系统中 MBUF 通常是预分配的有限资源池，泄露会导致后续所有网络通信失败
- **缓解因素**: 触发条件需要 `SOCK_RecvMbufEx_fl` 返回异常值，这取决于底层socket实现
