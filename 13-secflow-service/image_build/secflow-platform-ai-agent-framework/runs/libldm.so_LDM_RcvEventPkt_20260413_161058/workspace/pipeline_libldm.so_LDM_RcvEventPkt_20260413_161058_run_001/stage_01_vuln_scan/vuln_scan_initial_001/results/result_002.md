# 漏洞报告: ProtoType 字段写入缺乏范围校验可导致内存数据破坏

## 精确位置
- **函数名**: LDM_RcvEventPkt
- **源文件**: /home/qinghe/ai-workspace/target/libldm.so.c
- **漏洞代码位置**: 第368549行、第368551行
- **数据流关联**: 对应数据流分析 INPUT-4 (ProtoType) 的 EXPORT 终点

## 漏洞类型
- **CWE-754**: 不当检查意外条件
- **CWE-119**: 数组边界外操作 - 写入越界

## 严重性
**Medium** - ProtoType 值被直接写入到结构体的固定偏移位置（180），写入前缺乏范围检查，可能导致数据污染

## 源代码片段
```c
// libldm.so.c:368524 函数入口
__int64 __fastcall LDM_RcvEventPkt(__int64 a1, __int64 a2, __int64 a3)
{
  unsigned __int16 ProtoType; // ax
  // ...
  
  // 第368541-542: 获取 ProtoType
  ProtoType = MBUF_GetProtoType();
  v5 = ProtoType;
  if ( ProtoType != 88 )
  {
    // 第368547-555: 无范围校验直接写入结构体
    if ( (*(_BYTE *)(a1 + 16) & 2) != 0
      && (v6 = *(_QWORD *)(a1 + 904), v7 = *(unsigned __int16 *)(v6 + 108), (_WORD)v7)
      && (v8 = v6 + v7) != 0 )
    {
      *(_WORD *)(v8 + 180) = ProtoType;  // 直接写入，无范围检查
    }
    else
    {
      v15 = *(_QWORD *)(a3 + 24596);
      if ( v15 )
        *(_WORD *)(v15 + 180) = ProtoType;  // 另一处直接写入
    }
    // ...
  }
}
```

## 完整数据流与攻击路径
1. **输入源头**: INPUT-4 (ProtoType)，来自 MBUF_GetProtoType() 系统调用返回值
2. **传递路径**: 
   - MBUF_GetProtoType() → ProtoType (16位无符号整数)
   - ProtoType → *(_WORD *)(v8 + 180) 或 *(_WORD *)(v15 + 180)
3. **校验情况**: 
   - 仅检查 ProtoType != 88
   - **没有任何有效范围校验**！未检查 ProtoType 是否在有效协议范围内
4. **危险操作**: 
   - 将未验证的 ProtoType 值写入到结构体偏移 180 处
   - 可能覆盖后续字段导致数据结构损坏

## 触发条件
- 攻击者需要能够操控 MBUF 数据包中的协议类型字段
- 当 MBUF 解析出错或恶意构造协议类型时，可能写入非预期值
- 常见攻击场景：畸形数据包注入

## 影响评估
- **数据破坏**: ProtoType 被错误写入结构体，可能导致后续处理逻辑混乱
- **后续漏洞触发**: 错误的 ProtoType 可能导致错误的函数指针被调用（通过 LDM_GetFuncByPrototype）
- **拒绝服务**: 结构体数据损坏可能导致处理异常

## 补充说明：上游检查的存在

在 LDM_DispatchProcessByProType 函数中存在对 ProtoType 的范围检查（`ProtoType > 0x57u` 时触发断言），但该检查在漏洞触发**之后**执行，因为：

1. ProtoType 写入结构体偏移180的操作发生在 LDM_RcvEventPkt 中，早于调用 LDM_DispatchProcessByProType
2. 即使 ProtoType 超出有效范围，写入操作已经完成，无法阻止已发生的内存写入

## 修复建议
1. 对 ProtoType 值进行严格的范围校验（应小于等于 0x57 即 87）
2. 在写入结构体前验证目标地址的可用空间
3. 添加协议类型白名单验证
4. 记录异常的协议类型用于安全审计