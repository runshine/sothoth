# 污点流: name

## 污点源
- 参数: name (const char*) 🔴 TAINTED  
- 来源: 外部输入参数，来自 engines_discovery 调用者

## 当前函数内传播路径

### 直接使用
├── [L193] `strcasecmp(name, "lcr") == 0` → 🟢 CLEANED (条件比较，无污点传播)
├── [L199] `ERROR("Failed to initialize engine or runtime: %s", name)` → 🟡 EXPORT (日志函数)
├── [L200] `isulad_set_error_message("Failed to initialize engine or runtime: %s", name)` → 🟡 EXPORT (错误消息设置)
└── [L212] `conf_get_routine_rootdir(name)` → 📎 子函数接收污点

### 派生变量
- `rootpath` 🔴 TAINTED — 由 `conf_get_routine_rootdir(name)` 在 L212 返回后承载污点数据

## 新导入的污点对象
- `rootpath` 🔴 TAINTED — 由 `conf_get_routine_rootdir(name)` 返回值在 L212 写入
  - 路径由 `conf->json_confs->graph + "/" + ENGINE_ROOTPATH_NAME + "/" + name` 拼接而成

## 接收此污点的子函数
（只列在当前函数内调用的、实际接收此污点数据的函数）

| 函数 | 调用位置 | 接收的形参 |
|------|---------|-----------|
| conf_get_routine_rootdir | L212 | name |
| create_engine_root_path | L216 | rootpath (新导入污点载体) |

## 污点终点
| 终点 | 类型 | 位置 |
|------|------|------|
| conf_get_routine_rootdir(name) | 📎 子函数 | L212 |
| create_engine_root_path(rootpath) | 📎 子函数 | L216 |
| util_mkdir_p(path, mode) | ⚠️ DIRECT_SINK | create_engine_root_path 内部 (L133) |