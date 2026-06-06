# 数据流追踪: free_defs_mount

## 函数信息
- 文件: isula_libutils (external library)
- 行号: N/A
- 签名: void free_defs_mount(defs_mount *mnt)

## 数据流树状图

### INPUT-1: mnt (defs_mount *) 🔴 TAINTED
- 来源: 外部 CDI/NRI 挂载数据
└── [inferred] free_defs_mount() → 📌 USED
    ├── free(mnt->source) → consumed
    ├── free(mnt->destination) → consumed
    ├── free(mnt->type) → consumed
    ├── util_free_array_by_len(mnt->options, mnt->options_len) → 📎 util_free_array_by_len
    └── free(mnt) → consumed

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| mnt | free() | [inferred] | 终端沉点 |
| mnt->source | free() | [inferred] | 释放污点字符串 |
| mnt->destination | free() | [inferred] | 释放污点字符串 |
| mnt->type | free() | [inferred] | 释放污点字符串 |
| mnt->options | util_free_array_by_len | [inferred] | 释放污点数组 |

## ⚠️ DIRECT_SINK
无危险操作 — 仅将污点指针作为 free() 目标地址。

## 上游调用点
| 函数 | 文件 | 行号 |
|------|------|------|
| spec_add_mount | specs.c | L2800 |
| spec_remove_mount | specs.c | L2781 |
| append_additional_mounts | specs_mount.c | L142 |
| apply_cdi_mounts | cdi_container_edits.c | L390 |
| cdi_mounts_to_oci_mounts | cdi_container_edits.c | L256 |
