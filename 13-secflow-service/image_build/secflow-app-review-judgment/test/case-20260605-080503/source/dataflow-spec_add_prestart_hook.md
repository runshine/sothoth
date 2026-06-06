# 数据流追踪: spec_add_prestart_hook

## 函数信息
- 文件: src/daemon/modules/spec/specs.c
- 行号: L2810-L2830
- 签名: `int spec_add_prestart_hook(oci_spec_t *oci_spec, const defs_hook *prestart_hook)`

## 污点源
| 变量 | 类型 | 污点状态 | 来源 |
|------|------|----------|------|
| `prestart_hook` | defs_hook* | 🔴 TAINTED | 外部配置数据填充，蕴含 `说明` 字段 |

## 新导入的污点对象
| 对象 | 污点状态 | 产生方式 |
|------|----------|----------|
| `oci_spec->hooks->prestart[prestart_len]` | 🔴 TAINTED | [L2826] 通过写入操作 `oci_spec->hooks->prestart[prestart_len] = prestart_hook` 直接导入 |
| `oci_spec` (整体) | 🔴 TAINTED | 通过 hooks 数组向上传播至调用者上下文 |

## 传播路径图

### INPUT: prestart_hook (defs_hook*) 🔴 TAINTED
```
├── [L2814] if (prestart_hook == NULL) → 提前返回，不影响污点状态
├── [L2817] make_sure_oci_spec_hooks(oci_spec) 📎 子函数
│   └── 初始化 oci_spec->hooks（oci_spec 此时非污点，仅结构初始化）
├── [L2821-2822] util_mem_realloc → 🟡 EXPORT (标准库函数)
│   └── → oci_spec->hooks 数组扩展（为写入做准备）
└── [L2826] oci_spec->hooks->prestart[prestart_len] = prestart_hook ⚠️ DIRECT_SINK
    ├── 说明 字段随结构体整体隐式写入目标数组
    └── [L2827] oci_spec->hooks->prestart_len++
        └── → oci_spec（输出参数）🔴 TAINTED 向上传播
```

### NEW CARRIER: oci_spec->hooks->prestart[prestart_len] 🔴 TAINTED
```
└── 承载完整 defs_hook（含 说明），通过 oci_spec 输出参数向上传播
```

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `prestart_hook->说明` | ⚠️ DIRECT_SINK | L2826 | 字段随结构体隐式写入数组元素 |
| `oci_spec` | 📌 USED | L2827 | 输出参数携带污点向上传播 |
| `oci_spec->hooks->prestart[prestart_len]` | 📌 USED | L2826 | 数组元素承载污点 |

## 高危模式
- ⚠️ DIRECT_SINK: 结构体整体赋值 `oci_spec->hooks->prestart[prestart_len] = prestart_hook`，使包含 `说明` 字段在内的所有成员隐式写入目标数组

## 跟入子函数表
| 子函数 | 调用行 | 接收的形参 | 说明 |
|--------|--------|------------|------|
| make_sure_oci_spec_hooks | L2817 | oci_spec | 初始化 hooks 结构，oci_spec 此时未被污点污染 |

## 新导入污点对象的跟入
| 新污点载体 | 跟入函数 | 调用行 | 接收的形参 |
|------------|----------|--------|------------|
| oci_spec (输出参数) | - | - | 通过返回参数向上传播至调用者 |

---

## 汇总统计
- 初始污点数: 1
- 新导入污点对象: 2
- DIRECT_SINK 点: 1
- 跟入子函数: 1