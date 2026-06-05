## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `auth_desc` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `auth_state` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `chunk=tainted_mbuf_data` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |
| `chunk_len` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: AUTH_UPDATE

## 函数信息
- 文件: libipsec.c
- 上下文: IPSEC_ESP_HandleInputPkt (IPv6/IPv4) 子函数
- 签名: `AUTH_UPDATE(auth_desc, auth_state, data_ptr, data_len)` (宏展开为 `*(auth_desc+28)(auth_state, data_ptr, data_len)`)

## 污点源 (输入参数)

### INPUT-1: auth_desc (uint32_t *) 🔴 TAINTED
- 来源: 从 SADB 加载，`RAW_U64((void*)sa_entry, 16)` 获取
- 用途: auth_desc+28 存放更新回调函数指针
```
├── [L9498] AUTH_INIT(auth_desc, ...) → *(auth_desc+44) 初始化函数
├── [L9534] AUTH_UPDATE(auth_desc, auth_state[0], chunk, chunk_len)
│   └── ⚠️ DIRECT_SINK: *(auth_desc+28)(auth_state, chunk, chunk_len) — 函数指针解引用
├── [L9575] AUTH_INIT(auth_desc, ...) → *(auth_desc+44)
├── [L9576] AUTH_UPDATE(auth_desc, auth_state[0], computed_auth, RAW_U16(auth_desc,14))
│   └── ⚠️ DIRECT_SINK: *(auth_desc+28)(auth_state, computed_auth, tainted_len)
│   └── ⚠️ RAW_U16(auth_desc,14) 长度字段从污点 auth_desc 读取
└── [L9577] AUTH_FINAL(auth_desc, computed_auth, ...) → *(auth_desc+36) 最终函数
```

### INPUT-2: auth_state (int64_t / uint64_t[2]) 🔴 TAINTED
- 来源: 栈局部变量，由 `AUTH_INIT` 从 SADB/SA_ENTRY 写入，值受网络包 SPI 字段控制
- 传播: `auth_state[0]` 派生成新的污点载体
```
├── [L9498] AUTH_INIT(auth_desc, (int64_t *)auth_state, ...) → auth_state[0] 🔴 TAINTED
├── [L9534] AUTH_UPDATE(auth_desc, (int64_t)auth_state[0], chunk, chunk_len)
│   └── ⚠️ DIRECT_SINK: *(auth_desc+28)(auth_state[0], chunk, chunk_len) — 第一参数受污点
├── [L9577] AUTH_FINAL(auth_desc, computed_auth, (int64_t)auth_state[0], ...)
│   └── ⚠️ DIRECT_SINK: *(auth_desc+36) 函数指针解引用，auth_state[0] 参与
└── [L9576] AUTH_UPDATE(auth_desc, (int64_t)auth_state[0], computed_auth, RAW_U16(desc,14))
    └── ⚠️ DIRECT_SINK: *(auth_desc+28)(auth_state[0], computed_auth, tainted_len)
```

### INPUT-3: data_ptr (chunk / computed_auth) 🔴 TAINTED
- 来源: mbuf 网络负载数据，由 `MBUF_MakeMemoryContinuous_fl` 从 ESP 包提取
- 传播: computed_auth 由 `AUTH_FINAL` 对 chunk 计算 HMAC 后产生
```
├── [L9523] chunk = MBUF_MakeMemoryContinuous_fl(mbuf, chunk_offset, chunk_len, ...) → chunk 🔴 TAINTED
├── [L9534] AUTH_UPDATE(auth_desc, auth_state, chunk, chunk_len)
│   └── ⚠️ DIRECT_SINK: chunk 作为 data_ptr 传入外部 HMAC_Update 风格回调
├── [L9576] AUTH_FINAL(auth_desc, computed_auth, ...) → computed_auth 🔴 TAINTED
│   └── computed_auth 是 chunk 数据的 HMAC 计算结果
└── [L9579] AUTH_UPDATE(auth_desc, auth_state, computed_auth, auth_hash_len)
    └── computed_auth (🔴 TAINTED) 作为 data_ptr 传入第二阶段外部认证回调
```

### INPUT-4: data_len (chunk_len / auth_hash_len) 🔴 TAINTED
- 来源: 网络包长度字段 (authenticated_len, packet_info[6])
- 清洗: `if (chunk_len > 0x800) chunk_len = 2048;` — 被限制上限
```
├── [L9506] authenticated_len = packet_info[6] 🔴 TAINTED
├── [L9513] chunk_len = authenticated_len - processed_len 🔴 TAINTED
│   └── [L9515] if (chunk_len > 0x800) chunk_len = 2048; 🟢 CLEANED (capped)
├── [L9519] MBUF_MakeMemoryContinuous_fl(..., chunk_len) ⚠️ chunk_len 控制读取大小
└── [L9534, L9576, L9960, L10002] AUTH_UPDATE(..., ..., chunk_len/auth_hash_len)
    └── ⚠️ DIRECT_SINK: 长度参数传入函数指针调用
```

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| auth_desc | *(auth_desc+28) 函数指针解引用 | L9534, L9576, L9960, L10002 | 可导致任意代码执行 |
| auth_state[0] | *(auth_desc+28) 第一参数 | L9534, L9576, L9960, L10002 | 状态句柄受控 |
| chunk | *(auth_desc+28) data_ptr | L9534, L9960 | mbuf 网络数据传入回调 |
| computed_auth | *(auth_desc+28) data_ptr | L9576, L10002 | HMAC 结果传入回调 |
| chunk_len | *(auth_desc+28) data_len | L9534, L9960 | 读取大小可控（已限制2048） |
| RAW_U16(desc,14) | *(auth_desc+28) data_len | L9576, L10002 | 长度字段完全可控 |
| chunk_len | MBUF_MakeMemoryContinuous_fl size | L9519, L9957 | 长度控制从 mbuf 读取的字节数 |
| auth_desc+36 | *(auth_desc+36) 函数指针 | L9577, L10003 | 最终验证函数指针 |

## 新导入的污点载体 (从其他函数引入)

| 新对象 | 来源函数 | 用途 |
|--------|---------|------|
| auth_state[0] | AUTH_INIT | 状态上下文句柄，传入 AUTH_UPDATE |
| computed_auth | AUTH_FINAL | HMAC 结果，作为第二阶段 AUTH_UPDATE 的 data_ptr |
| chunk (derived) | MBUF_MakeMemoryContinuous_fl | mbuf 网络数据，作为第一阶段 AUTH_UPDATE 的 data_ptr |

## 关键 DIRECT_SINK 模式

```
⚠️ DIRECT_SINK: *(auth_desc+28)(auth_state, data_ptr, data_len)
   - 函数指针 *(auth_desc+28) 来自外部 SADB 输入
   - auth_state 由 AUTH_INIT 从 SADB 数据初始化
   - data_ptr 为网络包负载 (chunk) 或 HMAC 结果 (computed_auth)
   - data_len 来自网络包字段或 RAW_U16(auth_desc,14)
   - 任意参数组合均可导致任意代码执行

⚠️ DIRECT_SINK: *(auth_desc+36)(computed_auth, auth_state, lib_ctx, out_len)
   - 最终验证回调函数指针可控
```