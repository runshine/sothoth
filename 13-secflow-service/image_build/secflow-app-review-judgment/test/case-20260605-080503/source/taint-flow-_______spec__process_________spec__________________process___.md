# 数据流追踪: make_sure_oci_spec_process

## 函数信息
- 文件: src/daemon/modules/spec/specs_extend.c
- 行号: L506-L519
- 签名: `int make_sure_oci_spec_process(oci_runtime_spec *oci_spec)`

## 数据流树状图

### INPUT-1: oci_spec (oci_runtime_spec *) 🔴 TAINTED (外部输入/来自攻击者控制的 spec)
├── [L508] `if (oci_spec == NULL)` → NULL 检查，oci_spec 本身做防御性检查
├── [L511] `oci_spec->process == NULL` → ⚠️ **DIRECT_SINK**: 读取 oci_spec->process；当 oci_spec 指针受攻击者控制时，等同于对受控地址的解引用
│   └── [L511] `if (oci_spec->process == NULL)` → 条件判断：若 oci_spec 被攻击者控制，此处可触发对伪指针的访问
└── [L513] `oci_spec->process = util_common_calloc_s(sizeof(defs_process))` → ⚠️ **DIRECT_SINK**: 将分配的 defs_process* 写入 oci_spec->process；若 oci_spec 指针受攻击者控制，可写入攻击者指定的伪指针值
    └── [L516] `if (oci_spec->process == NULL)` → NULL 检查

### 传播路径说明

**核心路径**: `oci_spec` 参数自身 🔴 TAINTED → 通过 `oci_spec->process` 传播

1. **L511 读取污点字段**: 当 `oci_spec` 是攻击者伪造/控制的指针时，`oci_spec->process` 的读取等价于对任意受控地址的解引用，可导致非法内存访问
2. **L513 写入污点字段**: `util_common_calloc_s()` 返回值写入 `oci_spec->process`；若 `oci_spec` 指针受攻击者控制，攻击者可令其指向伪造结构，后续函数通过 `oci_spec->process->xxx` 访问时发生任意内存读写
3. **安全上下文**: 函数的目的是确保 `oci_spec->process` 已初始化；若 spec 来自外部攻击者配置文件（如容器 CDI/OCI JSON），攻击者可构造恶意 `process` 字段值，在下游函数（如 `refill_oci_process_capabilities`、`merge_env`）被利用

### 污点终点汇总
| 脏数据 | 终点类型 | 位置 | 说明 |
|--------|---------|------|------|
| oci_spec | ⚠️ DIRECT_SINK (读) | L511 | oci_spec->process 读取：受控指针解引用风险 |
| oci_spec | ⚠️ DIRECT_SINK (写) | L513 | oci_spec->process 写入：受控指针任意写风险 |
| util_common_calloc_s | 🟡 EXPORT | L513 | 标准内存分配 |