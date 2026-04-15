# 漏洞挖掘总结报告: IPSEC_SOCKI_PipeMsg

---

## 1.1 攻击面分析

### 目标函数

| 属性 | 值 |
|------|-----|
| **函数名** | `IPSEC_SOCKI_PipeMsg` |
| **签名** | `void __fastcall IPSEC_SOCKI_PipeMsg(int a1, unsigned int a2, unsigned int a3, __int64 a4)` |
| **源文件** | `/usr1/ipsec/ipsec_v8/src/ipsec/ipsec_sock_pipe.c` |
| **反编译位置** | `libipsec.so.c` L44686 |
| **注册方式** | `RTF_PipeMsgProcessFuncRegister(a2, IPSEC_SOCKI_PipeMsg)` @ L29810 |
| **系统角色** | VRP/RTF 管道消息框架的回调函数，负责接收管道通知、匹配管道类型、分发到IPSec数据处理链 |

### 功能概述
1. 根据 PipeID（a1）匹配管道类型（主管道/PP4/PP6/LDM/默认）
2. 确定写管道ID（v7）
3. 分发到 `IPSEC_SOCKI_HandlePipeData` → `IPSEC_SOCKI_PipeData`（10次重试）→ `IPSEC_SOCK_ProcPipeData`
4. 在 ProcPipeData 中：接收 MBUF 网络数据 → IPSec 加密/解密 → 转发到管道或 Socket

### 外部输入及攻击者控制能力

| INPUT | 类型 | 来源 | 描述 | 攻击者控制程度 |
|-------|------|------|------|---------------|
| INPUT-1 (a1) | `int` | RTF框架回调 | PipeID，管道标识 | 低：框架管理 |
| INPUT-2 (a2) | `unsigned int` | RTF框架回调 | 消息类型/命令（如0x3F0000） | 低：框架设置 |
| INPUT-3 (a3) | `unsigned int` | RTF框架回调 | 附加参数（0=普通/2=紧急） | 低：框架设置 |
| INPUT-4 (a4) | `__int64` | RTF框架回调 | IPSEC组件上下文结构体指针（1300+字节） | 极低：内部数据结构 |
| INPUT-5 | `unsigned char` | 全局变量 | `g_ucIpsecDebugEnv` 调试标志 | 极低：需管理面权限 |
| **v95 (MBUF)** | `__int64` | **网络** | **SOCK_RecvMbufEx_fl 接收的网络数据包** | **高：完全由攻击者控制** |

**关键洞察**: 函数的4个直接参数由框架设置，攻击者控制有限。真正的高风险攻击面是 `SOCK_RecvMbufEx_fl` 接收的网络数据包 v95 (MBUF)，其内容完全由网络攻击者控制。

---

## 1.2 分析覆盖度

| 数据流路径 | 起点 | 终点 | 终点类型 | EXPORT已跟入 | 漏洞模式已扫描 | 结论 |
|-----------|------|------|---------|-------------|---------------|------|
| INPUT-1 → v7赋值 | a1 | IPSEC_SOCKI_HandlePipeData 参数5 | 🟡 EXPORT | ✅ | ✅ | 漏洞: 管道ID伪造(result_003) |
| INPUT-1 → 管道匹配 | a1 | 与a4字段比较 | 📌 USED | ✅ | ✅ | 有符号混用(result_015) |
| INPUT-1 → AVL3树匹配 | a1 | VOS_AVL3树节点比较 | 📌 USED | ✅ | ✅ | 安全：存在性检查 |
| INPUT-1 → RecvMbuf | a1→v89[0] | SOCK_RecvMbufEx_fl 参数1 | 🟡 EXPORT | ✅(外部) | ✅ | 作为socketFD |
| INPUT-1 → SendToSocket | a1→v89[0] | IPSEC_SOCK_SendToSocket 参数1 | 🟡 EXPORT | ✅ | ✅ | 未使用的参数 |
| INPUT-2 → 消息类型判断 | a2 | `== 0x3F0000` 比较 | 📌 USED | ✅ | ✅ | 安全：常量比较 |
| INPUT-2 → HandlePipeData | a2 | 参数3(交换后) | 🟡 EXPORT | ✅ | ✅ | ProcPipeData中未使用(死参数) |
| INPUT-3 → HandlePipeData | a3 | 参数2(交换后) 白名单 | 🟢 CLEANED | ✅ | ✅ | 白名单{0,2}有效; else分支未初始化(result_001) |
| INPUT-3 → RecvMbufEx | a3→a2 | SOCK_RecvMbufEx_fl 参数2 | 🟡 EXPORT | ✅(外部) | ✅ | 仅0或2传入 |
| INPUT-4 → 上下文传递 | a4 | HandlePipeData 参数4 | 🟡 EXPORT | ✅ | ✅ | NULL检查存在 |
| INPUT-4 → 管道匹配 | a4+152/208/1296 | 与a1比较 | 📌 USED | ✅ | ✅ | 安全：控制流 |
| INPUT-4 → 写管道ID | a4+140/196/1256/8 | v7→HandlePipeData参数5 | 🟡 EXPORT | ✅ | ✅ | 内部结构值 |
| INPUT-4 → 调试路径 | a4+392/391/364等 | MakeDbgCompStrSetter/SSP_Debug | 📌 USED | ✅ | ✅ | 格式化安全(result_002) |
| INPUT-4 → 统计计数器 | a4+1232/1236/1248 | 递增操作 | [DEFERRED] | ✅ | ✅ | 溢出(result_011) |
| INPUT-4 → AVL3树 | a4+1032/1056 | VOS_AVL3_First/Next | 📌 USED | ✅(外部) | ✅ | 安全 |
| INPUT-5 → 控制流 | g_ucIpsecDebugEnv | 条件判断 | 📌 USED | ✅ | ✅ | 安全：仅影响日志 |
| v95(MBUF) → IPSec入方向 | 网络数据 | IPSEC_LIBI_HandleInputPkt/V4 | 🟡 EXPORT | ⚠️部分 | ✅ | 入口审计(result_016/019) |
| v95(MBUF) → IPSec出方向 | 网络数据 | IPSEC_LIBI_HandleOutputPkt/V4 | 🟡 EXPORT | ⚠️部分 | ✅ | SPI缺陷(result_017/019) |
| v95(MBUF) → PP6/PP4/LDM | 网络数据 | SendToPP6orPP4orLDMPipe | 🟡 EXPORT | ✅ | ✅ | 管道状态(result_018) |
| v95(MBUF) → Socket发送 | 网络数据 | IPSEC_SOCK_SendToSocket | 🟡 EXPORT | ✅ | ✅ | IPv6(result_009), 序列号(result_010) |
| v95(MBUF) → 调试拷贝 | 网络数据 | CopyDbgTracePacket→DbgTrace | 🟡 EXPORT | ✅ | ✅ | 缓冲区(result_013), 间接调用(result_014) |
| v95(MBUF) → 拥塞缓冲 | 网络数据 | IPSEC_SOCK_Buffer_Packet | 🟡 EXPORT | ✅ | ✅ | 资源限制(result_006) |

---

## 1.3 EXPORT 终点跟入汇总

| # | EXPORT 终点函数 | 跟入层级 | 跟入状态 | 发现 |
|---|---------------|---------|---------|------|
| 1 | IPSEC_SOCKI_HandlePipeData | 第1层 | ✅ 完整 | 未初始化返回值(result_001) |
| 2 | IPSEC_SOCKI_PipeData | 第2层 | ✅ 完整 | 重试循环DoS(result_004) |
| 3 | IPSEC_SOCK_ProcPipeData | 第3层 | ✅ 完整 | MBUF泄露(result_007), TOCTOU(result_005), 未初始化(result_008) |
| 4 | IPSEC_SOCK_Buffer_Packet | 第4层 | ✅ 完整 | 断言不阻断(result_006) |
| 5 | IPSEC_SOCK_SendToPP6orPP4orLDMPipe | 第4层 | ✅ 完整 | 管道状态检查(result_018); NULL/管道校验完整 |
| 6 | IPSEC_SOCK_SendToSocket | 第4层 | ✅ 完整 | IPv6标记(result_009), 断言绕过(result_012), 序列号(result_010) |
| 7 | IPSEC_SOCK_CopyDbgTracePacket | 第4层 | ✅ 完整 | 缓冲区大小未验证的256KB拷贝(result_013) |
| 8 | IPSEC_SOCK_DbgTracePacket | 第4层 | ✅ 完整 | 间接调用(result_014) |
| 9 | IPSEC_SOCK_GetLdmPipeLC | 第4层 | ✅ 完整 | 安全：AVL3遍历 |
| 10 | IPSEC_SOCK_GetLdmPipeMB | 第4层 | ✅ 完整 | 安全：简单条件返回 |
| 11 | IPSEC_MakeDbgCompStrSetter | 辅助 | ✅ 完整 | 格式化安全(result_002) |
| 12 | IPSEC_LIBI_HandleInputPkt/V4 | 第4层 | ⚠️ 部分 | 入口参数审计(result_016); 核心逻辑未深入(result_019) |
| 13 | IPSEC_LIBI_HandleOutputPkt/V4 | 第4层 | ⚠️ 部分 | SPI验证缺陷(result_017); 核心加密未深入(result_019) |
| 14 | SOCK_RecvMbufEx_fl | 外部库 | ❌ 未跟入 | VRP框架底层socket接收 |
| 15 | VOS_AVL3_First/Next/Find | 外部库 | ❌ 未跟入 | VRP框架AVL3树操作 |
| 16 | MBUF_Send_fl | 外部库 | ❌ 未跟入 | VRP框架MBUF发送 |
| 17 | MBUF_TokenAlloc_fl | 外部库 | ❌ 未跟入 | VRP框架MBUF令牌分配 |
| 18 | SSP_ProtocolPacketTrace | 外部库 | ❌ 未跟入 | 协议跟踪系统 |

---

## 1.4 关键发现验证

| # | 数据流关键发现 (★标记) | 验证状态 | 结论 | 关联报告 |
|---|---------------------|---------|------|---------|
| 1 | ★ SOCK_RecvMbufEx_fl 为核心网络数据入口 | ✅ 已验证 | 确认：唯一MBUF入口；异常返回路径存在泄露 | result_007 |
| 2 | ★ v95 (MBUF) 为新脏数据源 | ✅ 已验证 | 确认：流经IPSec处理、调试拷贝、管道/socket发送等多路径 | result_013, result_017, result_019 |
| 3 | ★ 参数交换 a2↔a3 | ✅ 已验证 | 确认：HandlePipeData(a1,**a3**,**a2**,a4,v7)交换正确，白名单检查原始a3 | result_001 |
| 4 | ★ v7 的5种来源路径 | ✅ 已验证 | 确认：5路径均覆盖；AVL3路径v7=a1为异常赋值 | result_003 |
| 5 | ★ MBUF数据拷贝到调试缓冲区 | ✅ 已验证 | 确认：256KB截断有效但目标缓冲区大小未验证 | result_013 |
| 6 | ★ MBUF指针存入拥塞链表(DEFERRED) | ✅ 已验证 | 确认：链表操作安全；断言不阻断缓冲过度增长 | result_006 |
| 7 | ★ MBUF最终通过MBUF_Send_fl发送 | ✅ 已验证 | 确认：发送前有令牌分配、管道状态检查 | result_018 |

### 🟢 CLEANED 终点验证

| 清洗点 | 验证结果 | 绕过可能性 | 关联报告 |
|--------|---------|-----------|---------|
| `!a2 \|\| a2 == 2` 白名单 | ✅ 有效 | 不可绕过（完备白名单） | result_001(else分支未初始化) |
| `v10 > 0x40000` 长度截断 | ⚠️ 部分有效 | 截断有效，但目标缓冲区可能 < 256KB | result_013 |
| SendToPP6... NULL检查 | ✅ 有效 | 不可绕过（4参数均检查+return） | — |
| `(v33-2) & 0xFFFFFFFD` 管道状态 | ⚠️ 与文档不一致 | 实际允许{2,4}非{2,3,6,7} | result_018 |

---

## 1.5 漏洞汇总表

| 编号 | 报告文件 | 函数 | CWE | 严重性 | 置信度 | 摘要 |
|------|---------|------|-----|--------|--------|------|
| 1 | result_001.md | IPSEC_SOCKI_HandlePipeData | CWE-457 | Medium | 高 | 未初始化变量返回（a2 ∉ {0,2}时） |
| 2 | result_002.md | IPSEC_MakeDbgCompStrSetter | CWE-787 | Low | 低 | 格式化缓冲区潜在溢出（被截断函数保护） |
| 3 | result_003.md | IPSEC_SOCKI_PipeMsg | CWE-20 | Medium | 中 | AVL3遍历中读管道ID直接作为写管道ID |
| 4 | result_004.md | IPSEC_SOCKI_PipeData | CWE-834 | Low | 中 | 10次重试循环的DoS放大效应 |
| 5 | result_005.md | IPSEC_SOCK_ProcPipeData | CWE-367 | Low | 低 | 拥塞节点v9的TOCTOU竞态（需并发） |
| 6 | result_006.md | IPSEC_SOCK_Buffer_Packet | CWE-770 | Medium | 中 | 断言不阻断导致缓冲区过度增长 |
| 7 | result_007.md | IPSEC_SOCK_ProcPipeData | **CWE-401** | **Medium** | **高** | **MBUF内存泄露（RecvMbuf异常返回路径）** |
| 8 | result_008.md | IPSEC_SOCK_ProcPipeData | CWE-457 | Low | 中 | 多个IDA标记的未初始化变量用于日志 |
| 9 | result_009.md | IPSEC_SOCK_SendToSocket | **CWE-476** | **Medium** | **高** | **IPv6路径ControlInfo缺失时协议族标记错误** |
| 10 | result_010.md | IPSEC_SOCK_SendToSocket | CWE-190 | Low | 低 | SA序列号回绕无检查 |
| 11 | result_011.md | IPSEC_SOCK_ProcPipeData | CWE-190 | Low | 低 | 统计计数器整数溢出（仅影响监控） |
| 12 | result_012.md | IPSEC_SOCK_SendToSocket | CWE-617 | Low | 中 | VRP_Assert后控制流允许NULL解引用 |
| 13 | result_013.md | IPSEC_SOCK_CopyDbgTracePacket | **CWE-120** | **Medium** | **中** | **调试缓冲区大小未验证的256KB拷贝** |
| 14 | result_014.md | IPSEC_SOCK_DbgTracePacket | CWE-822 | Low | 低 | 间接函数调用参数来自内部结构 |
| 15 | result_015.md | IPSEC_SOCKI_PipeMsg | CWE-681 | Low | 中 | a1有符号/无符号比较混用 |
| 16 | result_016.md | IPSEC_LIBI_HandleInputPkt | CWE-704 | Medium | 高 | a3参数低字节被覆盖为条件结果 |
| 17 | result_017.md | IPSEC_LIBI_HandleOutputPkt | **CWE-20** | **Medium** | **中** | **SPI边界检查缺陷——保留范围SPI可绕过** |
| 18 | result_018.md | IPSEC_SOCK_SendToPP6... | CWE-573 | Low | 高 | 管道状态检查允许{2,4}非文档{2,3,6,7} |
| 19 | result_019.md | IPSEC_LIBI_Handle*Pkt (4个) | **CWE-676** | **High** | **低** | **网络数据包核心处理——最高风险未审计攻击面** |

### 严重性分布

| 严重性 | 数量 | 编号 |
|--------|------|------|
| High | 1 | #19 |
| Medium | 8 | #1, #3, #6, #7, #9, #13, #16, #17 |
| Low | 10 | #2, #4, #5, #8, #10, #11, #12, #14, #15, #18 |

---

## 1.6 风险评估与修复建议

### 整体风险等级: **中等**

**评估依据**:
1. 函数直接参数（a1-a4）由 RTF 框架设置，攻击者控制有限
2. 最高风险来自 v95(MBUF) 网络数据包 → IPSEC_LIBI_Handle*Pkt（仅入口级审计，核心逻辑为审计盲区）
3. 已确认的最高置信度漏洞为 result_007 (MBUF内存泄露) 和 result_009 (IPv6协议族标记错误)
4. 代码整体使用了安全编码实践：`snprintf_truncated_s`、`memcpy_s`、stack canary、NULL指针检查
5. IPSEC_LIBI 层的 SPI 验证缺陷 (result_017) 是入口审计的有价值发现

### 修复优先级

| 优先级 | 编号 | 漏洞 | 修复建议 |
|--------|------|------|---------|
| **P0-紧急** | #19 | IPSEC_LIBI 核心未审计 | 对 `IPSEC_PKT_ParseAndVerifyHdr`、`IPSEC_ESP_Handle*Pkt`、`IPSEC_AH_Handle*Pkt` 进行独立深度安全审计 |
| **P1-高** | #7 | MBUF内存泄露 | 在 `v10 != -3840` 返回路径前添加 `MBUF_Destroy_fl(v95, ...)` |
| **P1-高** | #13 | 调试缓冲区拷贝 | 验证 `*(a2+1476)` 缓冲区分配大小，或将截断上限降低 |
| **P1-高** | #17 | SPI边界检查 | ESP SPI 和 AH SPI 应独立检查保留范围（≤255），不应使用 AND 条件 |
| **P2-中** | #1 | 未初始化返回 | `HandlePipeData` 的 else 分支设置 `result = 0` |
| **P2-中** | #9 | IPv6协议族标记 | `MBUF_GetControlInfo(a3, 8)` 返回NULL时设置错误处理/销毁MBUF |
| **P2-中** | #3 | 管道ID混淆 | 确认 AVL3 路径 v7=a1 的设计意图；否则使用节点中的写管道ID |
| **P2-中** | #6 | 断言不阻断 | `Buffer_Packet` 中断言失败后应 return 而非继续执行 |
| **P3-低** | #15 | 有符号比较 | a1 的类型或比较统一为 unsigned |
| **P3-低** | #5 | TOCTOU | 确认线程模型；多线程需加锁 |
| **P3-低** | #18 | 管道状态检查 | 确认状态值 2/4 的语义，验证是否遗漏合法状态 |

---

## 1.7 局限性与未覆盖区域

### 未完整跟入的 EXPORT 函数（按风险排序）

| # | 函数 | 跟入状态 | 风险等级 | 说明 |
|---|------|---------|---------|------|
| 1 | **IPSEC_PKT_ParseAndVerifyHdr** | ❌ 未审计 | **极高** | 网络包头解析——最可能存在缓冲区溢出 |
| 2 | **IPSEC_ESP_HandleInputPkt** | ❌ 未审计 | **极高** | ESP解密——填充oracle/缓冲区溢出风险 |
| 3 | **IPSEC_ESP_HandleOutputPkt** | ❌ 未审计 | 高 | ESP加密——MBUF扩展/加密操作 |
| 4 | **IPSEC_AH_HandleInputPkt** | ❌ 未审计 | 高 | AH验证——认证绕过风险 |
| 5 | **IPSEC_AH_HandleOutputPkt** | ❌ 未审计 | 中 | AH生成 |
| 6 | IPSEC_LIBI_HandleInputPkt/V4 | ⚠️ 入口审计 | 高 | 入口参数(result_016)，核心未深入(result_019) |
| 7 | IPSEC_LIBI_HandleOutputPkt/V4 | ⚠️ 入口审计 | 中 | SPI缺陷(result_017)，核心未深入(result_019) |
| 8 | SOCK_RecvMbufEx_fl | ❌ 未审计 | 中 | VRP框架底层socket接收 |
| 9 | VOS_AVL3_First/Next/Find | ❌ 未审计 | 低 | VRP框架AVL3树操作 |
| 10 | MBUF_Send_fl 等 MBUF_* | ❌ 未审计 | 低 | VRP框架MBUF管理 |

### 未完整追踪的路径
1. **[DEFERRED] 拥塞缓冲**: v95(MBUF) 存入链表后被 `IPSEC_MGTI_Remove_Packet` 消费 — 需分析解拥塞逻辑
2. **[DEFERRED] 计数器**: a4+1232/1236/1248 写入后被监控模块读取 — 影响有限

### 需要额外分析的方向
1. **IPSEC_LIBI 层 (P0)**: 处理网络数据包的核心层，最高风险。特别是 `ParseAndVerifyHdr`（包头解析）、`ESP_HandleInputPkt`（解密）、`AH_HandleInputPkt`（认证）
2. **线程模型**: VRP/RTF 框架的并发模型影响 TOCTOU/竞态漏洞的实际可利用性
3. **调试缓冲区 `*(v11+1476)` 分配大小**: 确认 result_013 的严重性
4. **管道状态值语义**: 确认 `(v33-2) & 0xFFFFFFFD` 中 2 和 4 代表什么状态
5. **SA配置路径**: 管理面配置对SA节点值的影响

---

## 自检清单

- [x] summary.md 包含全部 7 个章节 (1.1-1.7)
- [x] 数据流的每个 EXPORT 终点在 1.2 覆盖度表和 1.3 汇总表中有记录
- [x] 数据流的 ★ 关键发现全部有验证结论 (1.4 节 7 项)
- [x] 每个漏洞报告有 ≥5 行代码片段
- [x] 每个漏洞有从 INPUT 到危险操作的完整路径
- [x] results/ 命名严格符合 result_NNN.md (001-019)
- [x] 1.5 汇总表 19 条与 results/ 19 个文件一一对应
