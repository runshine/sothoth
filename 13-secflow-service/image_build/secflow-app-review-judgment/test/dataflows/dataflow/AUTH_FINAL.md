## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `auth_desc` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `computed_auth` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `auth_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `lib_ctx` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: AUTH_FINAL

## 函数信息
- 文件: libipsec.c
- 函数名: AUTH_FINAL
- 污点输入参数:
  - `auth_desc` (uint32_t*) 🔴 TAINTED — 从 SA 数据库查询，SPI 来自外部网络输入
  - `computed_auth` (uint8_t[64]) 🔴 TAINTED — 由 AUTH_FINAL 宏输出（初始由调用者传入）
  - `auth_state[0]` 🔴 TAINTED — 由 AUTH_UPDATE 累积网络包数据
  - `lib_ctx` 🔴 TAINTED — 外部网络上下文参数

## 新导入的污点对象 (Within AUTH_FINAL)

| 变量 | 类型 | 污点来源 | 行号 |
|------|------|----------|------|
| `computed_auth` | uint8_t[64] | AUTH_FINAL 宏写入 out_buf | L9573, L9577, L9999, L10003 |
| `received_auth` | uint8_t[64] | MBUF_CopyDataFromMBufToBuffer 写入 | L9504, L1088 |

## 数据流树状图

### INPUT-1: auth_desc (uint32_t*) 🔴 TAINTED
├── [L498] AUTH_INIT(auth_desc, state, sa_entry, 1)
│   └── ⚠️ DIRECT_SINK: auth_desc+44 指针算术 → 虚函数查找
├── [L573] AUTH_FINAL(auth_desc, computed_auth, ...)
│   ├── ⚠️ DIRECT_SINK: auth_desc+36 指针算术 → 虚函数查找
│   └── computed_auth ← 🔴 TAINTED (算法输出)
├── [L576] AUTH_UPDATE(auth_desc, state, computed_auth, RAW_U16(auth_desc,14))
│   ├── computed_auth 🔴 TAINTED → 作为算法输入
│   ├── RAW_U16(auth_desc,14) 🔴 TAINTED → 从 tainted 结构读长度
│   └── ⚠️ DIRECT_SINK: auth_desc+28 指针算术 → 虚函数查找
└── [L579] VOS_MemCmp(computed_auth, received_auth, ...)
    └── 📌 USED: computed_auth 🔴 TAINTED 参与认证比较

### INPUT-2: computed_auth (uint8_t[64]) 🔴 TAINTED
├── [L9573] AUTH_FINAL(auth_desc, computed_auth, ..., 64)
│   └── computed_auth ← 🔴 TAINTED (新导入对象)
├── [L9575] AUTH_INIT(auth_desc, ..., sa_entry, 0) — 重新初始化
├── [L9577] AUTH_UPDATE(auth_desc, auth_state[0], computed_auth, RAW_U16(auth_desc+14))
│   ├── computed_auth 🔴 TAINTED → 作为 data_ptr 传入
│   └── ⚠️ DIRECT_SINK: data_len 由 auth_desc+14 提供（attacker-controlled）
├── [L9579] AUTH_FINAL(auth_desc, computed_auth, ..., 64)
│   └── ⚠️ DIRECT_SINK: 再次写入 computed_auth
└── [L9582] VOS_MemCmp(computed_auth, received_auth, auth_hash_len_field)
    └── 📌 USED: 用于认证结果比较判断

### INPUT-3: auth_state[0] 🔴 TAINTED
├── [L9498] AUTH_INIT(state) → 用 sa_entry 数据初始化
├── [L9534] AUTH_UPDATE(auth_state[0], chunk, chunk_len)
│   └── auth_state[0] 累积网络包数据
├── [L9573] AUTH_FINAL(..., (int64_t)auth_state[0], ...)
│   ├── computed_auth ← 🔴 TAINTED (新导入对象)
│   └── ⚠️ DIRECT_SINK: auth_state[0] 作为 state_handle 传入外部函数
│       └── 🟡 EXPORT: 外部函数指针目标未知
├── [L9575] AUTH_INIT(state) → 状态重新初始化
├── [L9576] AUTH_UPDATE(auth_state[0], computed_auth, ...)
│   ├── auth_state[0] 包含 computed_auth
│   └── ⚠️ DIRECT_SINK: computed_auth 作为 data_ptr
└── [L9577] AUTH_FINAL(..., (int64_t)auth_state[0], ...)
    └── ⚠️ DIRECT_SINK: 同上风险

### INPUT-4: lib_ctx 🔴 TAINTED
├── [L9378] RAW_U64((void *)lib_ctx, 16) → offset 🔴 TAINTED
│   └── MBUF_MakeMemoryContinuous_fl(..., offset, ...)
│       ⚠️ DIRECT_SINK: offset由lib_ctx+16控制,可能导致内存访问越界
├── [L9396] RAW_U64((void *)lib_ctx, 16) → 再次作为MBUF偏移参数
│   └── MBUF_MakeMemoryContinuous_fl(mbuf, offset, 24, ...)
├── [L9410] RAW_U8((void *)lib_ctx, 400/403)
│   └── 条件判断 → 🟢 不传播
├── [L9419] VOS_AVL3_Find(lib_ctx+120, &key, lib_ctx+144)
│   └── SA查找参数
├── [L9434] VOS_AVL3_Find(lib_ctx+76, ptr, lib_ctx+100)
│   └── SADB查找参数
├── [L9524] RAW_U64((void *)lib_ctx, 16) → chunk连续化偏移
│   └── chunk = MBUF_MakeMemoryContinuous_fl(..., chunk_len, offset, ...)
├── [L9573] AUTH_FINAL(..., lib_ctx, 64)
│   ├── lib_ctx 作为第3参数传入虚函数
│   └── ⚠️ DIRECT_SINK: 间接虚函数调用
└── [L9581] (const char *)(lib_ctx + 448) → SSP_Debug(...)
    └── 调试字符串参数

### New Tainted Object: received_auth 🔴 TAINTED (新导入)
├── [L9504/L1088] MBUF_CopyDataFromMBufToBuffer(mbuf, ..., received_auth)
│   └── 从网络包复制 auth_hash_len 字节
└── [L579/L9582] VOS_MemCmp(computed_auth, received_auth, ...)
    └── 📌 USED: 参与认证比较

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `auth_desc` | ⚠️ DIRECT_SINK | L498, L573, L576 | 指针算术+虚函数查找 |
| `auth_state[0]` | ⚠️ DIRECT_SINK | L9573, L9577 | 作为函数指针参数，可能被外部密码库解引用 |
| `auth_state[0]` | 📌 USED | L9534, L9576 | 参与 HMAC 计算 |
| `computed_auth` | ⚠️ DIRECT_SINK | L9577, L10002 | 作为 AUTH_UPDATE 的 data_ptr |
| `computed_auth` | 📌 USED | L579, L9582, L10006 | 与 received_auth 做认证校验 |
| `lib_ctx+16` | ⚠️ DIRECT_SINK | L9378, L9396, L9524 | 作为 MBUF 偏移参数，越界访问风险 |

## 安全风险

### ⚠️ 高危 DIRECT_SINK 汇总

1. **间接函数调用 (L9573, L9577, L9999, L10003)**
   - AUTH_FINAL 通过 `auth_desc+36` 函数指针表间接调用
   - auth_desc 来自外部 SA 条目，可被攻击者覆写
   - 风险: 控制流劫持 → 代码执行

2. **外部函数指针解引用 (L9573, L9577)**
   - `auth_state[0]` 作为 `state_handle`（int64_t）传入外部密码库
   - 如果外部函数将其解释为指针而未做验证
   - 风险: 越界内存访问、信息泄露、认证绕过

3. **MBUF 偏移参数 (L9378, L9396, L9524)**
   - `RAW_U64((void *)lib_ctx, 16)` 作为内存连续化请求的偏移量
   - 若 lib_ctx+16 处值被污染，可能导致越界内存访问
   - 风险: 内存越界访问 → 信息泄露/损坏

4. **Attacker-controlled length field (L576, L9576, L10002)**
   - `RAW_U16(auth_desc, 14)` 提供 data_len 参数
   - auth_desc 来自外部 SA 条目，长度字段可控
   - 风险: 缓冲区溢出、数据截断