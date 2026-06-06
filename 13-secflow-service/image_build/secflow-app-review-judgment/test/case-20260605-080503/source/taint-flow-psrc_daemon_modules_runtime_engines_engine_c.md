# 污点流: psrc/daemon/modules/runtime/engines/engine.c

## 污点源
- psrc/daemon/modules/runtime/engines/engine.c 🔴 TAINTED
  - engine.c L212: `rootpath = conf_get_routine_rootdir(name)` — 运行时根路径，daemon 配置决定
  - engine.c L218: `create_engine_root_path(rootpath)` — 目录创建并写入 process.json
  - engine.c 中 rootpath 经 daemon 配置后写入 process.json

## 新导入的污点对象
- `buffer->contents` 🔴 TAINTED — 由 `buffer->nappend()` 在 L1139 写入
- `p->root_path` 🔴 TAINTED — 由 `buffer->to_str(buffer)` 在 L1145 写入

## 传播路径

```
psrc/daemon/modules/runtime/engines/engine.c 🔴 TAINTED
├── [engine.c L212] rootpath = conf_get_routine_rootdir(name) → rootpath 🔴 TAINTED
└── [engine.c L218] create_engine_root_path(rootpath)
    └── process.json 🔴 TAINTED (daemon 管理)
            ↓
process.json 🔴 TAINTED
    └── [process.c L64] shim_client_process_state_parse_file("process.json")
        └── p->state->runtime 🔴 TAINTED ← 核心危险入口点
            └── init_root_path(process_t *p) ← 当前函数
                ├── [L1113] state_path = isula_strdup_s(p->workdir)
                │   └── state_path 🔴 TAINTED
                ├── [L1133] buffer = isula_buffer_alloc(PATH_MAX) — 干净
                ├── [L1139] buffer->nappend(buffer, PATH_MAX, "%s/%s", state_path, p->state->runtime)
                │   └── ⚠️ DIRECT_SINK: 污点格式化写入
                │   └── buffer->contents 🔴 TAINTED [NEW CARRIER]
                └── [L1145] p->root_path = buffer->to_str(buffer)
                    └── ⚠️ DIRECT_SINK: 污点转字符串
                    └── p->root_path 🔴 TAINTED [NEW CARRIER]
                        └── [L1273] set_common_params() → params[] → execvp()
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| Buffer::nappend | L1139 | buffer, state_path, runtime |
| Buffer::to_str | L1145 | buffer |
| set_common_params | L1273 | p->root_path |