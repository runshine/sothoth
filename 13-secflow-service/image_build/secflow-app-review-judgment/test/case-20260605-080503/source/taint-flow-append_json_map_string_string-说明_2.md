# 污点流: 说明:

## 污点源
- 说明: 🔴 TAINTED — `value` (第3形参，`const char *`)，外部调用者传入容器注解值/配置数据

## 新导入的污点对象
- `map->values[]` 🔴 TAINTED — 由 `append_json_map_string_string` 内部 `util_strdup_s(value)` 写入后成为新污点载体
- `map->keys[]` 🔴 TAINTED — 由 `append_json_map_string_string` 内部 `util_strdup_s(key)` 写入后成为新污点载体

## 传播路径
```
### 说明: 🔴 TAINTED (value，形参)
├── [入口] 空指针检查 (map==NULL || key==NULL || value==NULL) → NULL 则提前返回
├── [内部] util_strdup_s(value) → 说明: 🔴 TAINTED 直接拷贝
│   └── 写入 map->values[map->len] → map->values[] 🔴 TAINTED (新污点载体)
├── [内部] util_strdup_s(key) → key 🔴 TAINTED 直接拷贝 (key 也来自外部)
│   └── 写入 map->keys[map->len] → map->keys[] 🔴 TAINTED (新污点载体)
├── [内部] map->len += 1
└── [返回] return 0
    └── 调用者上下文 (specs.c L125):
        ERROR("... value:%s", values[i]) ⚠️ DIRECT_SINK (format string)
        ├── values[i] 🔴 TAINTED 作为 %s 格式参数
        └── keys[i] 🔴 TAINTED 作为 %s 格式参数
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| `util_strdup_s` (内部) | append_json_map_string_string | value, key |
| `util_smart_calloc_s` (内部) | append_json_map_string_string | size (干净) |
| `ERROR` 宏 (调用点) | specs.c L125 | values[i] ⚠️ DIRECT_SINK |