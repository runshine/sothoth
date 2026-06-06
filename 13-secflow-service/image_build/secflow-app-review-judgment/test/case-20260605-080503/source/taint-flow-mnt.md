# 污点流: mnt

## 污点源
- `mnt` (defs_mount *) 🔴 TAINTED — 外部 NRI 插件传入的挂载数据，对应字段 destination/type/source/options 均来自外部输入

## 新导入的污点对象
- `oci_spec->mounts[n]` 🔴 TAINTED — 由 L2808 的赋值操作 `oci_spec->mounts[oci_spec->mounts_len] = mnt` 写入

## 传播路径
```
### INPUT-1: mnt (defs_mount *) 🔴 TAINTED
├── [L2796] if (oci_spec == NULL || mnt == NULL) → 条件判断，仅作空值检查，不传播污点
└── [L2808] oci_spec->mounts[oci_spec->mounts_len] = mnt
    └── oci_spec->mounts[n] 🔴 TAINTED（新污点载体，外部数据存入 OCI 规范挂载数组）
        └── [L2809] oci_spec->mounts_len++ → 计数器递增，干净操作
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| *(无)* | — | `mnt` 未作为参数传入任何子函数；`util_mem_realloc` 为标准内存分配器，仅操作 `oci_spec->mounts` 指针和大小，不接收 `mnt` |

## DIRECT_SINK 检查
| 操作 | 行号 | 结果 |
|------|------|------|
| `oci_spec->mounts_len + 1` 作为分配计数传入 `util_mem_realloc` | L2800 | ✅ 非 sink：`mounts_len` 为可信计数器，非污点数据 |
| `oci_spec->mounts[idx] = mnt` | L2808 | ✅ 非 sink：指针赋值，无越界风险（索引来自可信计数器） |
| `oci_spec->mounts_len++` | L2809 | ✅ 非 sink：可信计数器自增 |

**⚠️ 本函数体内未发现 DIRECT_SINK 操作。**

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `mnt` → `oci_spec->mounts[n]` | 📌 USED | L2808 | 污点数据存入 OCI 运行时规范挂载数组，供后续容器配置使用 |