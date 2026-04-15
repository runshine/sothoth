# 漏洞报告: 调试日志可能泄露系统内部信息

## 精确位置
- **函数名**: IPSEC_SOCKI_PipeMsg, IPSEC_SOCK_ProcPipeData
- **源文件**: /home/qinghe/ai-workspace/target_libipsec/libipsec.so.c
- **漏洞代码行**: L44704-L44716, L44724-L44738 等多处

## 漏洞类型与 CWE
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor（敏感信息未授权泄露）

## 严重性与置信度
严重性: Low
置信度: 中

## 源代码片段
```c
// L44704-L44716 (调试级别1路径)
if ( *(_BYTE *)(a4 + 392) == 1 )  // 调试级别1
{
  v8 = "SLAVE";
  if ( !*(_DWORD *)(a4 + 364) )
    v8 = "MASTER";
  IPSEC_MakeDbgCompStrSetter(
    a4,
    16,
    62,
    (unsigned int)"[IPSEC-%s-%x] Recieved pipe message for pipe Id = %u, PP6 Pipe Id = %d, PP4 Pipe Id= %d, LDM MB Pipe Id = %d",
    (_DWORD)v8,
    *(_DWORD *)(a4 + 4));  // 组件实例ID
  // ... 日志输出
}
```

## 泄露的信息

### 1. 管道ID信息
- 当前处理的消息管道ID
- PP6 管道ID
- PP4 管道ID
- LDM MB 管道ID

### 2. 系统配置信息
- 组件实例ID (a4+4)
- 主从角色 (MASTER/SLAVE)
- 部署类型 (deploytype)

### 3. 网络包信息
- VR ID (虚拟路由器ID)
- VS 节点信息
- 包处理结果

## 完整攻击路径

### 触发条件
1. 全局调试标志 `g_ucIpsecDebugEnv` 被设置为非零值
2. 或者组件调试级别标志 (a4+391, a4+392) 被设置为1

### 攻击场景
- 如果攻击者能够启用调试模式
- 可以获取系统内部管道配置信息
- 有助于后续攻击（如漏洞报告001中利用管道ID）

## 影响评估

**信息泄露风险**:
- 攻击者可获取系统管道布局
- 有助于了解系统架构和进行针对性攻击

**风险等级**: Low
- 调试模式通常在生产环境关闭
- 信息价值取决于攻击者的能力水平

## 缓解措施

1. 确保生产环境关闭调试模式
2. 审计日志输出权限控制
3. 考虑对敏感信息进行脱敏处理