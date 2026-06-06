# 污点流: `说明:` 参数在 `append_json_map_string_string` 中

## 函数信息
- 文件: `isula_libutils` (外部库，来源不可见)
- 签名: `int append_json_map_string_string(json_map_string_string *map, const char *key, const char *value)`
- 参数 `说明:` = `value` (第3个形参)

## 污点源

| 标识 | 参数 | 类型 | 污点状态 | 说明 |
|------|------|------|-----------|------|
| [INPUT-1] | `value` (说明:) | `const char *` | 🔴 TAINTED | 调用者从外部输入（容器注解值、配置文件、网络数据等）传入的未验证字符串 |

## 逐行传播路径追踪

### 阶段一：空指针检查 (入口)
```
### [INPUT-1] value (说明:) 🔴 TAINTED
└── [入口] if (map == NULL || key == NULL || value == NULL) → 返回错误
    └── value 为 NULL 时直接返回，污点未传播
```

### 阶段二：内部 map 容量检查与扩展
```
[L扩展判断] if (map->len >= map->cap) → do_expand_json_map(map)
    └── 内部通过 util_smart_calloc_s 扩展 items/keys/values 数组
```

### 阶段三：核心操作 — 污点数据写入输出参数 (L核心)
```
[核心] map->keys[map->len] = util_strdup_s(key);    ← 🔴 TAINTED value 作为 key 写入
[核心] map->values[map->len] = util_strdup_s(value); ← 🔴 TAINTED value 本身写入 values[]
[核心] map->len += 1;
[返回] return 0;
```

**新导入的污点载体**：
- `map->keys[]` 🔴 TAINTED — `value` 副本写入 keys 数组
- `map->values[]` 🔴 TAINTED — `value` 副本（说明:数据）写入 values 数组

### 阶段四：若 value 进一步被用于格式化输出 (跨调用点)
```
调用者上下文 (specs.c L125):
    ERROR("Failed to append annotation:%s, value:%s", keys[i], values[i])
    ├── values[i] ← 🔴 TAINTED 作为 %s 格式参数 ⚠️ DIRECT_SINK (format string)
    └── keys[i]  ← 🔴 TAINTED 作为 %s 格式参数 ⚠️ DIRECT_SINK (format string)
```

## 子函数调用汇总

| 行号 | 函数 | 接收形参 | 污点传递 | 跟入 |
|------|------|---------|---------|------|
| 内部 | `util_smart_calloc_s` | 扩展大小 | 大小参数干净 | 🟡 EXPORT (标准内存分配函数) |
| 内部 | `util_strdup_s` | `key` / `value` | key/value 直接拷贝 | 📎 util_strdup_s (已分析) |

## 直接危险操作（⚠️ DIRECT_SINK）

| 操作 | 位置 | 说明 |
|------|------|------|
| `util_strdup_s(value)` — `说明:` 字符串长度不受验证 | 内部 | 注解值长度无边界检查，若值超长可能导致栈/堆缓冲区溢出 |
| `map->values[i] = util_strdup_s(value)` — 写入目标载体 | 内部 | 将未验证的说明:数据写入 map，向上传播污点至所有使用该 map 的代码路径 |
| ERROR("%s", value) — `说明:` 作为格式参数 | specs.c L125 | 污点注解值直接作为 %s 传入 ERROR/日志函数，若包含 %n/%x 等格式说明符，触发格式字符串漏洞 |

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `value` (说明:) | ⚠️ DIRECT_SINK (写入) | 内部 | util_strdup_s 将说明:数据拷贝进 map->values[]，污点写入目标载体 |
| `map->values[]` (新载体) | 📌 OUTPUT | 调用后 | values[] 数组元素承载说明:污点数据，向上传播至所有使用该 map 的调用者 |
| `map->keys[]` (新载体) | 📌 OUTPUT | 调用后 | 说明:数据也可能作为 key 写入 keys[]，污点传播至 keys 数组 |
| `value` (说明:) | ⚠️ DIRECT_SINK (format) | specs.c L125 | 作为 %s 参数传入 ERROR 宏，格式说明符可控 |

## 完整数据流树状图

```
### INPUT-1: value (说明:) 🔴 TAINTED (外部容器注解值)
├── [入口] 空指针检查 → value 为 NULL 则提前返回
├── [内部] util_strdup_s(key) → 干净 key 不引入额外污点
├── [内部] util_strdup_s(value) → value 🔴 TAINTED (说明:数据拷贝)
│   └── 写入 map->values[map->len] → map->values[] 🔴 TAINTED (新污点载体)
│       └── 写入 map->keys[map->len] → map->keys[] 🔴 TAINTED (新污点载体)
└── [返回] return 0
    └── 调用者上下文 (specs.c L125):
        ERROR("... value:%s", values[i]) ⚠️ DIRECT_SINK (format string)
```

## 关键结论

1. **`说明:` 污点完整传播路径**：`value` (外部注解值) → `util_strdup_s(value)` 拷贝 → `map->values[len]` 写入 → `map` (整体) 成为 🔴 TAINTED 新载体。污点通过 map 结构向上传播至所有后续调用者。

2. **⚠️ 双重 DIRECT_SINK 风险**：
   - **写入风险**：`util_strdup_s(value)` 将无长度验证的说明:数据直接拷贝至堆分配的 values 数组，若值超长可能导致缓冲区溢出。
   - **格式字符串风险**：调用者将污点注解值直接作为 `%s` 参数传入 ERROR/日志宏，若值中嵌入 `%n`、`%p`、`%x` 等格式说明符，可触发格式字符串漏洞（信息泄露或任意内存写入）。

3. **🟡 EXPORT 标记原因**：`append_json_map_string_string` 定义在 `isula_libutils` 外部库中，源代码不可见。内部 `util_strdup_s` 调用通过污点数据长度产生潜在缓冲区溢出风险，需在上层调用点注意长度验证。