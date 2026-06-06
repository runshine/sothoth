# 污点流: new_engine_locked

## 污点源
- new_engine_locked: 🔴 TAINTED — 参数 `name` (const char*)，来自 `engines_discovery` 调用者

## 新导入的污点对象
- `rootpath` 🔴 TAINTED — 由 `conf_get_routine_rootdir(name)` 在 L212 返回后写入，路径由 `conf->json_confs->graph + "/engines/" + name` 拼接而成

## 传播路径
```
name 🔴 TAINTED (L190)
├── [L193] strcasecmp(name, "lcr") == 0 → 🟢 CLEANED
├── [L198] ERROR("...", name) → 🟡 EXPORT
├── [L199] isulad_set_error_message("...", name) → 🟡 EXPORT
├── [L207] ERROR("Init engine: %s log failed", name) → 🟡 EXPORT
└── [L212] rootpath = conf_get_routine_rootdir(name) → rootpath 🔴 TAINTED
    └── [L216] create_engine_root_path(rootpath) → ⚠️ DIRECT_SINK
        └── util_mkdir_p(path, mode) — 污点路径用于目录创建操作
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|-----------|
| conf_get_routine_rootdir | L212 | name |
| create_engine_root_path | L216 | rootpath |