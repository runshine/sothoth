# 数据流追踪: make_sure_oci_spec_linux_resources

## 函数信息
- 文件: src/daemon/modules/spec/specs_extend.c
- 行号: L521-L539
- 签名: `int make_sure_oci_spec_linux_resources(oci_runtime_spec *oci_spec)`

## 数据流树状图

### INPUT-1: oci_spec (oci_runtime_spec *) 🔴 TAINTED
├── [L523-525] if (oci_spec == NULL) → 防御性检查，无传播
├── [L527] make_sure_oci_spec_linux(oci_spec) → 📎 见 tainted.list
│   └── [make_sure_oci_spec_linux 内部, L495-498] 若 oci_spec->linux 为 NULL 则分配
└── [L538] return 0 → 🟢 CLEAN

## 污点终点汇总
| 脏数据 | 终点类型 | 位置 | 说明 |
|--------|---------|------|------|
| oci_spec | 📎 子函数 | L527 | 传入 make_sure_oci_spec_linux 进行 linux 子结构初始化 |