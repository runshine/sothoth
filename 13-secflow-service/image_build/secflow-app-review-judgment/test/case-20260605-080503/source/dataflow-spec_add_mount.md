# 数据流追踪: spec_add_mount

## 函数信息
- 文件: src/daemon/modules/spec/specs.c
- 签名: `int spec_add_mount(oci_runtime_spec *oci_spec, defs_mount *mnt)`

## 数据流树状图

### INPUT-1: mnt (defs_mount *) 🔴 TAINTED
├── [L2796] if (oci_spec == NULL || mnt == NULL) → 条件判断，仅作空值检查，不传播污点
├── [L2802] ERROR("Out of memory") → 错误日志记录，干净操作
└── [L2808] oci_spec->mounts[oci_spec->mounts_len] = mnt
    └── `oci_spec->mounts[n]` 🔴 TAINTED（新导入的污点载体）
        └── [L2809] oci_spec->mounts_len++ → 计数器递增（干净操作）

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `mnt` → `oci_spec->mounts[n]` | 📌 USED | L2808 | 污点数据存入 OCI 运行时规范挂载数组，供后续容器配置使用 |