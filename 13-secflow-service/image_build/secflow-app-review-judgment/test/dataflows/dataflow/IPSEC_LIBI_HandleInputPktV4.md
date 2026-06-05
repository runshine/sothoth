## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `mbuf` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIBI_HandleInputPktV4

## 函数信息
- 文件: libipsec.c
- 行号: L11800-L11870
- 签名: `void IPSEC_LIBI_HandleInputPktV4(void* lib_ctx, int64_t mbuf, int* proto_out, void* stats_ctx)`

## 污点源

| 参数 | 类型 | 状态 | 说明 |
|------|------|------|------|
| mbuf | int64_t | 🔴 TAINTED | 外部网络输入，承载原始IPv4/IPSec数据包 |

## 新导入的污点对象

| 对象 | 类型 | 引入位置 | 说明 |
|------|------|---------|------|
| parse_state | uint8_t[64] | L11827 | 由 IPSEC_PKT_ParseAndVerifyHdrV4 调用 MBUF_MakeMemoryContinuous_fl 读取mbuf数据后写入，64字节全部从网络数据中提取（版本、协议、IP头长度、总长度、源/目的IP、SPI、端口等） |

## 数据流树状图

### INPUT-1: mbuf (int64_t) 🔴 TAINTED
├── [L11809] MBUF_GetReceiveIfIndex(mbuf, ...) → mbuf 保持污点 🔴 TAINTED
├── [L11827] IPSEC_PKT_ParseAndVerifyHdrV4(mbuf, lib_ctx, parse_state, stats_ctx) → **parse_state 成为新污点载体** 🔴 TAINTED
│   ├── [L11829] RAW_U32(parse_state, PST_DST4_RAW) → dst_ipv4 🔴 TAINTED
│   │   └── [L11838] IPSEC_PKT_DebugPacketV4(..., dst_ipv4, ...) → 🟡 EXPORT（调试函数）
│   ├── [L11830] IPSEC_LIBI_GetManualSa(lib_ctx, parse_state, 0) → 📎 见跟入列表
│   ├── [L11831] RAW_U8(parse_state, PST_PROTO) → 条件判断
│   ├── [L11838] RAW_U8(parse_state, PST_PROTO) → 条件判断
│   ├── [L11840] IPSEC_AH_HandleInputPktV4(lib_ctx, mbuf, parse_state, stats_ctx) → 📎 见跟入列表
│   │   └── ⚠️ DIRECT_SINK: 子函数内 parse_state[0..3]（packet_info[0]）控制 MBUF_MakeMemoryContinuous_fl 的读取偏移/长度；parse_state[4]（packet_info[4]）控制 VRP_Malloc_F 分配大小和 MBUF_CopyDataFromMBufToBuffer 拷贝长度
│   └── [L11868] IPSEC_ESP_HandleInputPktV4(lib_ctx, mbuf, parse_state, stats_ctx) → 📎 见跟入列表
│       └── ⚠️ DIRECT_SINK: 子函数内 parse_state[0..3]（packet_info[0]）控制 MBUF_MakeMemoryContinuous_fl 的读取偏移；parse_state[4]（packet_info[4]）控制 payload_len 计算，进而影响 ESP 载荷处理
└── [L11840] *proto_out = 51 → 🟢 已清洗（常量赋值）
    [L11868] *proto_out = 50 → 🟢 已清洗（常量赋值）

### parse_state 🔴 TAINTED（由mbuf导出）
├── [L11829] RAW_U32(parse_state, PST_DST4_RAW) → dst_ipv4 🔴 TAINTED
│   └── [L11838] IPSEC_PKT_DebugPacketV4(..., dst_ipv4, ...) → 🟡 EXPORT（调试函数）
├── [L11830] IPSEC_LIBI_GetManualSa(lib_ctx, parse_state, 0) → 📎 见跟入列表
├── [L11831/L11838] RAW_U8(parse_state, PST_PROTO) → 条件判断，无新污点变量
├── [L11840] IPSEC_AH_HandleInputPktV4(mbuf, parse_state, ...) → 📎 见跟入列表
│   └── ⚠️ DIRECT_SINK: 子函数内 parse_state[0..3] 控制 mbuf 内存连续化范围；parse_state[4] 控制堆内存分配和缓冲区拷贝大小
└── [L11868] IPSEC_ESP_HandleInputPktV4(mbuf, parse_state, ...) → 📎 见跟入列表
    └── ⚠️ DIRECT_SINK: 子函数内 parse_state[0..3] 控制 mbuf 内存连续化偏移；parse_state[4] 影响 payload_len 计算

## 污点终点汇总

| 脏数据 | 终点类型 | 位置 | 说明 |
|--------|---------|------|------|
| mbuf | 📎 CALLEE | L11827 | 传入 IPSEC_PKT_ParseAndVerifyHdrV4 解析并生成 parse_state |
| mbuf | 📎 CALLEE | L11840 | 传入 IPSEC_AH_HandleInputPktV4 处理AH协议包 |
| mbuf | 📎 CALLEE | L11868 | 传入 IPSEC_ESP_HandleInputPktV4 处理ESP协议包 |
| parse_state | 📎 CALLEE | L11830 | 传入 IPSEC_LIBI_GetManualSa 获取SA条目，SPI字段来自mbuf |
| parse_state | 📎 CALLEE | L11840 | 传入 IPSEC_AH_HandleInputPktV4，控制内存访问和分配大小 |
| parse_state | 📎 CALLEE | L11868 | 传入 IPSEC_ESP_HandleInputPktV4，控制内存访问和payload长度 |
| dst_ipv4 | 🟡 EXPORT | L11838 | 传入调试函数 IPSEC_PKT_DebugPacketV4 |
| *proto_out | 🟢 CLEANED | L11840/L11868 | 已通过常量赋值(51/50)清洗 |

## 高危模式

| 污点字段 | 高危模式 | 说明 |
|---------|---------|------|
| parse_state[0..3] | ⚠️ DIRECT_SINK | 控制 mbuf 内存连续化操作的读取偏移和长度，可能导致越界读取 |
| parse_state[4] | ⚠️ DIRECT_SINK | 控制堆内存分配大小和缓冲区拷贝长度，可能导致堆溢出或缓冲区越界 |