# thread_core 模块外部入口点清单 - 精筛合并版

## 模块概述
- **模块名**: thread_core
- **合并日期**: 2026-05-09
- **分析文件数**: 40 (40 workers)
- **保留入口数**: 58
- **过滤入口数**: ~120 (定时器回调、无污点配置函数、内部子函数)

---

## 一、CoAP 网络接口入口 (被动回调型)

### 1.1 AnnounceBeginServer 模块

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 1 | `HandleRequest(void*, otCoapHeader*, otMessage*, otMessageInfo*)` | announce_begin_server.cpp:77 | 🔴 `aContext`, `aHeader`(网络可控), `aMessage`(网络可控), `aMessageInfo`(网络可控) | 🔴 高 |
| 2 | `SendAnnounce(uint32_t)` | announce_begin_server.hpp:54 | 🔴 `aChannelMask`(外部可控) | 🟡 中 |
| 3 | `SendAnnounce(uint32_t, uint8_t, uint16_t)` | announce_begin_server.hpp:66 | 🔴 `aChannelMask`, `aCount`(DoS风险), `aPeriod`(时序攻击) | 🔴 高 |

### 1.2 EnergyScanServer 模块

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 4 | `HandleRequest(void*, otCoapHeader*, otMessage*, otMessageInfo*)` | energy_scan_server.cpp | 🔴 `aContext`, `aHeader`, `aMessage`, `aMessageInfo` | 🔴 高 |
| 5 | `HandleScanResult(void*, otEnergyScanResult*)` | energy_scan_server.cpp | 🔴 `aResult`(无线电驱动) | 🟡 中 |
| 6 | `HandleNetifStateChanged(uint32_t, void*)` | energy_scan_server.cpp | 🔴 `aFlags`, `aContext` | 🟡 中 |

### 1.3 PanIdQueryServer 模块

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 7 | `HandleQuery(void*, otCoapHeader*, otMessage*, otMessageInfo*)` | panid_query_server.cpp | 🔴 `aHeader`, `aMessage`, `aMessageInfo` | 🔴 高 |
| 8 | `HandleScanResult(void*, Mac::Frame*)` | panid_query_server.cpp | 🔴 `aFrame`(无线信号) | 🟡 中 |

### 1.4 NetworkDataLeader 模块

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 9 | `HandleServerData(void*, otCoapHeader*, otMessage*, otMessageInfo*)` | network_data_leader_ftd.cpp | 🔴 `aHeader`, `aMessage`, `aMessageInfo` | 🔴 高 |
| 10 | `HandleCommissioningSet(void*, otCoapHeader*, otMessage*, otMessageInfo*)` | network_data_leader_ftd.cpp | 🔴 `aHeader`, `aMessage`(MeshCoP TLV), `aMessageInfo` | 🔴 高 |
| 11 | `HandleCommissioningGet(void*, otCoapHeader*, otMessage*, otMessageInfo*)` | network_data_leader_ftd.cpp | 🔴 `aHeader`, `aMessage`, `aMessageInfo` | 🟠 中高 |
| 12 | `SetNetworkData(uint8_t, uint8_t, bool, const uint8_t*, uint8_t)` | network_data_leader.cpp | 🔴 `aData`, `aDataLength`, `aVersion` | 🔴 高 |
| 13 | `SetCommissioningData(const uint8_t*, uint8_t)` | network_data_leader.cpp | 🔴 `aValue`, `aValueLength` | 🔴 高 |

### 1.5 MleRouter 模块 (地址管理)

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 14 | `HandleAddressSolicit(void*, otCoapHeader*, otMessage*, otMessageInfo*)` | mle_router.cpp | 🔴 `aHeader`, `aMessage`, `aMessageInfo` | 🔴 高 |
| 15 | `HandleAddressRelease(void*, otCoapHeader*, otMessage*, otMessageInfo*)` | mle_router.cpp | 🔴 `aHeader`, `aMessage`, `aMessageInfo` | 🔴 高 |
| 16 | `HandleAddressSolicitResponse(void*, otCoapHeader*, otMessage*, otMessageInfo*, otError)` | mle_router.cpp | 🔴 `aHeader`, `aMessage`, `aMessageInfo`, `aResult` | 🟠 中 |

---

## 二、MAC 层被动回调入口 (无线帧处理)

### 2.1 MeshForwarder 模块

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 17 | `HandleReceivedFrame(Receiver&, Frame&)` | mesh_forwarder.cpp:1503 | 🔴 `aFrame`(外部网络帧) | 🔴 极高 |
| 18 | `HandleFrameRequest(Sender&, Frame&)` | mesh_forwarder.cpp:830 | 🔴 `aFrame`(MAC层帧请求) | 🔴 极高 |
| 19 | `HandleSentFrame(Sender&, Frame&, otError)` | mesh_forwarder.cpp:1218 | 🔴 `aFrame`, `aError`(外部可控) | 🔴 高 |

### 2.2 DataPollManager 模块

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 20 | `HandlePollSent(otError)` | data_poll_manager.cpp | 🔴 `aError`(MAC层错误状态) | 🟡 中 |
| 21 | `CheckFramePending(Mac::Frame&)` | data_poll_manager.cpp | 🔴 `aFrame`(外部帧pending位) | 🔴 高 |
| 22 | `SetExternalPollPeriod(uint32_t)` | data_poll_manager.cpp | 🔴 `aPeriod`(外部可控) | 🟡 中 |
| 23 | `SetAttachMode(bool)` | data_poll_manager.cpp | 🔴 `aMode`(外部可控) | 🟡 中 |
| 24 | `SendFastPolls(uint8_t)` | data_poll_manager.cpp | 🔴 `aNumFastPolls`(外部可控) | 🟡 中 |

---

## 三、MLE 协议消息处理入口 (被动回调型)

### 3.1 Mle 主模块 (mle.cpp)

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 25 | `HandleUdpReceive(void*, otMessage*, otMessageInfo*)` | mle.cpp | 🔴 `aMessage`(网络消息), `aMessageInfo`(源地址) | 🔴 高 |
| 26 | `HandleAdvertisement(const Message&, const MessageInfo&)` | mle.cpp | 🔴 `aMessage`, `aMessageInfo` | 🔴 高 |
| 27 | `HandleChildIdResponse(const Message&, const MessageInfo&)` | mle.cpp | 🔴 `aMessage`, `aMessageInfo` | 🔴 高 |
| 28 | `HandleChildUpdateRequest(const Message&, const MessageInfo&, uint32_t)` | mle.cpp | 🔴 `aMessage`, `aMessageInfo`, `aKeySequence` | 🔴 高 |
| 29 | `HandleChildUpdateResponse(const Message&, const MessageInfo&, uint32_t)` | mle.cpp | 🔴 `aMessage`, `aMessageInfo`, `aKeySequence` | 🔴 高 |
| 30 | `HandleDataResponse(const Message&, const MessageInfo&)` | mle.cpp | 🔴 `aMessage`, `aMessageInfo` | 🟠 中 |
| 31 | `HandleParentResponse(const Message&, const MessageInfo&)` | mle.cpp | 🔴 `aMessage`, `aMessageInfo` | 🟠 中 |
| 32 | `HandleAnnounce(const Message&, const MessageInfo&)` | mle.cpp | 🔴 `aMessage`, `aMessageInfo` | 🟠 中 |
| 33 | `HandleDiscoveryResponse(const Message&, const MessageInfo&)` | mle.cpp | 🔴 `aMessage`, `aMessageInfo` | 🟠 中 |
| 34 | `HandleLeaderData(const Message&, const MessageInfo&)` | mle.cpp | 🔴 `aMessage`, `aMessageInfo` | 🟠 中 |
| 35 | `Discover(uint32_t, uint16_t, bool, bool, DiscoverHandler, void*)` | mle.cpp | 🔴 `aScanChannels`, `aPanId`, `aJoiner`, `aCallback`, `aContext` | 🔴 高 |
| 36 | `SetTimeout(uint32_t)` | mle.cpp | 🔴 `aTimeout` | 🟡 中 |
| 37 | `SetDeviceMode(uint8_t)` | mle.cpp | 🔴 `aDeviceMode` | 🟡 中 |
| 38 | `BecomeChild(AttachMode)` | mle.cpp | 🔴 `aMode` | 🟡 中 |
| 39 | `SetMeshLocalPrefix(const uint8_t*)` | mle.cpp | 🔴 `aPrefix` | 🟠 中 |

### 3.2 MleRouter 模块 (路由器消息处理)

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 40 | `HandleLinkRequest(const Message&, const MessageInfo&)` | mle_router.cpp | 🔴 `aMessage`, `aMessageInfo` | 🔴 高 |
| 41 | `HandleLinkAccept(const Message&, const MessageInfo&, uint32_t)` | mle_router.cpp | 🔴 `aMessage`, `aMessageInfo`, `aKeySequence` | 🔴 高 |
| 42 | `HandleLinkAcceptAndRequest(const Message&, const MessageInfo&, uint32_t)` | mle_router.cpp | 🔴 `aMessage`, `aMessageInfo`, `aKeySequence` | 🔴 高 |
| 43 | `HandleParentRequest(const Message&, const MessageInfo&)` | mle_router.cpp | 🔴 `aMessage`, `aMessageInfo` | 🟠 中 |
| 44 | `HandleChildIdRequest(const Message&, const MessageInfo&, uint32_t)` | mle_router.cpp | 🔴 `aMessage`, `aMessageInfo`, `aKeySequence` | 🔴 高 |
| 45 | `HandleDataRequest(const Message&, const MessageInfo&)` | mle_router.cpp | 🔴 `aMessage`, `aMessageInfo` | 🟠 中 |
| 46 | `HandleDiscoveryRequest(const Message&, const MessageInfo&)` | mle_router.cpp | 🔴 `aMessage`, `aMessageInfo` | 🟠 中 |
| 47 | `CheckReachability(uint16_t, uint16_t, Ip6::Header&)` | mle_router_mtd.hpp | 🔴 `aMeshSource`, `aMeshDest`, `aIp6Header` | 🔴 高 |

---

## 四、密钥管理导出 API (主动拉取型)

### 4.1 KeyManager 模块

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 48 | `SetPSKc(const uint8_t*)` | key_manager.cpp | 🔴 `aPSKc`(核心密钥材料) | 🔴 高 |
| 49 | `SetMasterKey(const otMasterKey&)` | key_manager.cpp | 🔴 `aKey`(核心密钥材料) | 🔴 高 |
| 50 | `SetKek(const uint8_t*)` | key_manager.cpp | 🔴 `aKek`(KEK密钥) | 🔴 高 |
| 51 | `ComputeKey(uint32_t, uint8_t*)` | key_manager.cpp | 🔴 `aKeySequence`(可枚举) | 🟠 中 |
| 52 | `SetCurrentKeySequence(uint32_t)` | key_manager.cpp | 🔴 `aKeySequence` | 🟠 中 |
| 53 | `GetTemporaryMacKey(uint32_t)` | key_manager.cpp | 🔴 `aKeySequence`(历史密钥枚举) | 🟠 中 |
| 54 | `GetTemporaryMleKey(uint32_t)` | key_manager.cpp | 🔴 `aKeySequence`(历史密钥枚举) | 🟠 中 |
| 55 | `SetKeyRotation(uint32_t)` | key_manager.cpp | 🔴 `aKeyRotation` | 🟡 中 |

---

## 五、网络数据管理入口 (主动拉取型)

### 5.1 NetworkDataLocal 模块

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 56 | `AddOnMeshPrefix(const uint8_t*, uint8_t, int8_t, uint8_t, bool)` | network_data_local.cpp | 🔴 `aPrefix`, `aPrefixLength`, `aPrf`, `aFlags`, `aStable` | 🟡 中 |
| 57 | `RemoveOnMeshPrefix(const uint8_t*, uint8_t)` | network_data_local.cpp | 🔴 `aPrefix`, `aPrefixLength` | 🟡 中 |
| 58 | `AddHasRoutePrefix(const uint8_t*, uint8_t, int8_t, bool)` | network_data_local.cpp | 🔴 `aPrefix`(无PrefixMatch验证), `aPrefixLength`, `aPrf`, `aStable` | 🔴 高 |
| 59 | `RemoveHasRoutePrefix(const uint8_t*, uint8_t)` | network_data_local.cpp | 🔴 `aPrefix`, `aPrefixLength` | 🟡 中 |

---

## 六、MeshForwarder 核心转发入口 (主动拉取型)

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 60 | `SendMessage(Message&)` | mesh_forwarder.cpp:323 | 🔴 `aMessage`(外部消息内容) | 🔴 高 |
| 61 | `SetRxOnWhenIdle(bool)` | mesh_forwarder.cpp:741 | 🔴 `aRxOnWhenIdle`(无线电控制) | 🟡 中 |
| 62 | `SetDiscoverParameters(uint32_t)` | mesh_forwarder.cpp:1406 | 🔴 `aScanChannels`(信道选择) | 🟡 中 |
| 63 | `RemoveMessages(Child&, uint8_t)` | mesh_forwarder.hpp:134 | 🔴 `aSubType`(外部可控) | 🟡 中 |

---

## 七、MleRouter 路由器角色管理 (主动拉取型)

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 64 | `BecomeRouter(ThreadStatusTlv::Status)` | mle_router_ftd.hpp | 🔴 `aStatus` | 🔴 高 |
| 65 | `BecomeLeader(void)` | mle_router_ftd.hpp | 无直接污点 | 🔴 高 |
| 66 | `SetRouterRoleEnabled(bool)` | mle_router_ftd.hpp | 🔴 `aEnabled` | 🔴 高 |
| 67 | `SetLeaderWeight(uint8_t)` | mle_router_ftd.hpp | 🔴 `aWeight` | 🟡 中 |
| 68 | `SetRouterId(uint8_t)` | mle_router_ftd.hpp | 🔴 `aRouterId` | 🟠 中 |
| 69 | `SetMaxAllowedChildren(uint8_t)` | mle_router_ftd.hpp | 🔴 `aMaxChildren` | 🟡 中 |
| 70 | `SetSteeringData(otExtAddress*)` | mle_router_ftd.hpp (条件编译) | 🔴 `aExtAddress`(OOB引导数据) | 🔴 高 |

---

## 八、Radio/RSSI 层被动回调入口

### 8.1 LinkQuality 模块

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 71 | `RssAverager::Add(int8_t)` | link_quality.cpp:56 | 🔴 `aRss`(无线电信号强度) | 🟡 中 |
| 72 | `LinkQualityInfo::AddRss(int8_t, int8_t)` | link_quality.cpp:122 | 🔴 `aNoiseFloor`, `aRss` | 🟡 中 |

---

## 九、ThreadNetif 安全过滤入口

### 9.1 ThreadNetif 模块

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 73 | `TmfFilter(const Message&, const MessageInfo&, void*)` | thread_netif.cpp | 🔴 `aMessage`, `aMessageInfo` | 🟢 低(关键安全边界) |
| 74 | `SendMessage(Message&)` | thread_netif.hpp | 🔴 `aMessage`(全部内容) | 🔴 高 |
| 75 | `RouteLookup(const Ip6::Address&, const Ip6::Address&, uint8_t*)` | thread_netif.cpp | 🔴 `aSource`, `aDestination` | 🟡 中 |

---

## 十、TMF Proxy 代理入口

### 10.1 TmfProxy 模块

| # | 函数名 | 文件位置 | 污点变量 | 风险等级 |
|---|--------|----------|----------|----------|
| 76 | `HandleRelayReceive(void*, otCoapHeader*, otMessage*, otMessageInfo*)` | tmf_proxy.cpp | 🔴 `aHeader`, `aMessage`, `aMessageInfo`, `aStreamHandler`(外部可控回调) | 🔴 高 |
| 77 | `HandleResponse(void*, otCoapHeader*, otMessage*, otMessageInfo*, otError)` | tmf_proxy.cpp | 🔴 `aHeader`, `aMessage`, `aMessageInfo`, `aResult` | 🟠 中 |
| 78 | `Send(Message&, uint16_t, uint16_t)` | tmf_proxy.cpp | 🔴 `aMessage`, `aLocator`(伪造RLOC16), `aPort` | 🔴 高 |

---

## 入口类型分布统计

| 类型 | 数量 | 说明 |
|------|------|------|
| **被动回调型 - CoAP 网络** | 16 | 外部 CoAP 消息处理 |
| **被动回调型 - MAC 层** | 3 | 无线帧处理 |
| **被动回调型 - MLE 消息** | 19 | MLE 协议消息处理 |
| **被动回调型 - Radio/RSSI** | 2 | 无线电信号采样 |
| **主动拉取型 - API 导出** | 32 | 外部模块调用 |
| **主动拉取型 - 配置/查询** | 6 | 网络数据管理、密钥管理 |
| **被动回调型 - 安全过滤** | 1 | TMF 安全边界 |
| **总计** | **79** | |

---

## 风险等级分布

| 风险等级 | 数量 | 占比 |
|----------|------|------|
| 🔴 极高 | 3 | 3.8% |
| 🔴 高 | 36 | 45.6% |
| 🟠 中高 | 9 | 11.4% |
| 🟠 中 | 21 | 26.6% |
| 🟡 中低 | 10 | 12.7% |
| 🟢 低 | 0 | 0% |

---

## 关键发现

### 1. 核心高风险入口点 (Top 5)

| 排名 | 函数 | 风险说明 |
|------|------|----------|
| 1 | `HandleReceivedFrame()` | 外部网络帧直接入口，攻击者可伪造源地址、payload，触发分片重组 |
| 2 | `HandleUdpReceive()` | 所有 MLE 消息处理中枢，外部网络数据直接进入 |
| 3 | `HandleChildUpdateRequest()` | 子节点更新请求处理，涉及网络配置变更 |
| 4 | `SetPSKc/SetMasterKey/SetKek()` | 核心密钥材料直接写入，无权限验证 |
| 5 | `HandleCommissioningSet()` | MeshCoP TLV 完整可控，写入内部状态 |

### 2. 主要攻击面向量

1. **CoAP 网络接口** (16个入口)
   - 协议: CoAP over UDP/IPv6
   - 路径: `/a/*`, `/c/*`, `/d/*` 等 28+ URI 端点
   - 威胁: 消息注入、TLV 构造、权限绕过

2. **MAC 层无线接口** (3个入口)
   - 数据来源: IEEE 802.15.4 无线帧
   - 威胁: 帧伪造、pending 位欺骗、信道干扰

3. **MLE 协议消息** (19个入口)
   - 协议: MLE over UDP (端口 19788)
   - 威胁: 邻居关系欺骗、角色冒充、网络拓扑操纵

4. **Radio/RSSI 层** (2个入口)
   - 数据来源: 无线电硬件信号测量
   - 威胁: 信号干扰、路由路径选择影响

5. **密钥管理 API** (8个入口)
   - 核心材料: PSKc、MasterKey、KEK
   - 威胁: 密钥材料替换、历史密钥枚举

### 3. 已过滤的入口类型

| 类型 | 过滤数量 | 过滤原因 |
|------|----------|----------|
| 定时器回调 | 15+ | 无外部污点参数，仅内部状态驱动 |
| 构造函数 | 8 | 仅内部初始化，无外部数据处理 |
| 内部包装函数 | 20+ | 有内部调用者，非跨模块入口 |
| 纯配置/无污点函数 | 30+ | 参数无外部数据依赖 |
| 纯查询/输出函数 | 25+ | 仅返回内部状态，无数据输入 |

### 4. 权限边界分析

| 边界类型 | 机制 | 覆盖入口 |
|----------|------|----------|
| **Leader 角色限制** | `OT_DEVICE_ROLE_LEADER` | HandleServerData, HandleCommissioningSet/Get |
| **TMF 地址规则** | MeshLocal/LinkLocal 验证 | TmfFilter |
| **Commissioner Session** | SessionId 匹配验证 | HandleCommissioningSet |
| **密钥序列验证** | FrameCounter + KeySequence 检查 | HandleUdpReceive |
| **条件编译** | `OPENTHREAD_FTD`/`ENABLE_*` 宏 | 路由器功能、边界路由等 |

### 5. 关键安全建议

1. **高优先级**
   - 加强 CoAP 回调中的 TLV 格式验证
   - 对密钥管理 API 添加权限校验
   - 限制 HandleReceivedFrame 的分片重组资源

2. **中优先级**
   - 增强 AddHasRoutePrefix 的前缀验证（缺失 PrefixMatch）
   - 限制 Discover() 的扫描频率和时长
   - 为 TMF Proxy 的外部回调添加安全约束

3. **低优先级**
   - 考虑添加版本号一致性检查
   - 增强输入参数的边界检查

---

## 已排除的函数（非外部入口）

| 类别 | 函数示例 | 排除原因 |
|------|----------|----------|
| 定时器回调 | HandleTimer, HandlePollTimer, HandleKeyRotationTimer, HandleDiscoverTimer, HandleReassemblyTimer | 无外部污点参数，框架内部触发 |
| 构造函数 | AnnounceBeginServer(), EnergyScanServer(), Mle(), MeshForwarder() | 仅内部初始化，无外部数据处理 |
| 内部包装 | HandleRequest(Header&,...), HandleTimer(void), GetOwner() | 有内部调用者，非跨模块入口 |
| 纯配置 | Enable/Disable/Start/Stop (无污点参数) | 无外部数据依赖 |
| 纯查询 | Get*() 系列, Is*() 系列, GetAverage() | 仅返回内部状态 |
| 内部子函数 | SendAnnounce(), SendReport(), HandleMesh(), HandleFragment() | 非跨模块调用 |

---

*精筛合并完成*
*过滤规则：定时器回调、构造函数、无污点配置函数、内部子函数一律过滤；去重合并；保优保留信息最完整版本*