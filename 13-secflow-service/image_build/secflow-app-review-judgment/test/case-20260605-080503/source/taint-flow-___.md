# 污点流: 说明:

## 污点源
- `说明:` (即形参 `o`, cdi_container_edits *) 🔴 TAINTED — 调用者从外部 CDI JSON Spec 文件解析后传入（通过 `cdi_spec_get_edits` / `cdi_device_get_edits` 获取）。其 `envs[]`、`device_nodes[]`、`hooks[]`、`mounts[]` 字段承载外部输入污点数据

## 新导入的污点对象
- `e` (cdi_container_edits *) 🔴 TAINTED — 由 `append_env/append_device_nodes/append_hooks/append_mounts` 将 `o` 的污点字段写入 `e` 后引入。`e` 原为干净输出参数，append 操作后成为携带污点数据的新载体，在 cdi_cache.c:485 传递给 `cdi_container_edits_apply`

## 传播路径
```
### 说明: (o, cdi_container_edits *) 🔴 TAINTED
├── [空检查] if (o == NULL) return 0 → 📌 USED (仅条件比较)
├── [空检查] if (e == NULL) ERROR(...) return -1 → 📌 USED (仅条件比较)
├── [L?]  append_env(e, o, util_strdup_s) → 🟡 EXPORT
│          o->envs[] 🔴 TAINTED → e->envs[] 🔴 TAINTED
│              └── e 🔴 TAINTED（新引入污点载体）
├── [L?]  append_device_nodes(e, o, clone_cdi_device_node) → 🟡 EXPORT
│          o->device_nodes[] 🔴 TAINTED → e->device_nodes[] 🔴 TAINTED
│              └── e 🔴 TAINTED（累积污染）
├── [L?]  append_hooks(e, o, clone_cdi_hook) → 🟡 EXPORT
│          o->hooks[] 🔴 TAINTED → e->hooks[] 🔴 TAINTED
│              └── e 🔴 TAINTED（累积污染）
└── [L?]  append_mounts(e, o, clone_cdi_mount) → 🟡 EXPORT
           o->mounts[] 🔴 TAINTED → e->mounts[] 🔴 TAINTED
               └── e 🔴 TAINTED（累积污染）
                   └── cdi_cache.c:465/471 → 返回
                       └── 📎 cdi_container_edits_apply
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| append_env | L? | `o`（源引用）, `e`（目标引用） |
| append_device_nodes | L? | `o`（源引用）, `e`（目标引用） |
| append_hooks | L? | `o`（源引用）, `e`（目标引用） |
| append_mounts | L? | `o`（源引用）, `e`（目标引用） |
| cdi_container_edits_apply | cdi_cache.c:485 | `e`（新污点载体，由调用者传递） |

> **注**: 源文件 `cdi_container_edits.c` 为 marker（58 bytes），函数实现在外部 `isula_libutils` 库，行号不可精确确定。`append_*` 函数由宏 `EDITS_APPEND_ITEM_DEF` 生成（静态函数），按规则标记为 🟡 EXPORT。