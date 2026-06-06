# 数据流追踪: make_sure_oci_spec_process

## 函数信息
- 文件: src/daemon/modules/spec/specs_extend.c
- 行号: 510-518
- 签名: `int make_sure_oci_spec_process(oci_runtime_spec *oci_spec)`

## 污点源
- oci_spec (oci_runtime_spec*) 🔴 TAINTED — 函数参数，外部输入

## 数据流树状图

### INPUT-1: oci_spec (oci_runtime_spec*) 🔴 TAINTED
├── [L510] oci_spec->process == NULL
│   └── ⚠️ DIRECT_SINK: 污点指针解引用，访问process字段
├── [L512] oci_spec->process = util_common_calloc_s(sizeof(defs_process))
│   └── ⚠️ DIRECT_SINK: 污点指针控制写入目标
│       └── oci_spec->process 🔴 TAINTED (新污点载体)
│           └── 该字段由调用方访问/修改，作为返回值被使用
└── [L518] return 0
    └── 🟢 CLEANED (返回状态码，非污点数据)

## 新导入的污点对象
| 对象 | 创建位置 | 说明 |
|------|---------|------|
| oci_spec->process | L512 | 由污点指针 oci_spec 写入创建的新污点载体 |

## DIRECT_SINK 标注
| 行号 | 危险操作 | 描述 |
|------|---------|------|
| L510 | oci_spec->process == NULL | 污点指针解引用访问process字段 |
| L512 | oci_spec->process = ... | 污点指针 oci_spec 控制写入目标地址 |

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| oci_spec | ⚠️ DIRECT_SINK | L510 | 污点指针解引用，访问process字段进行空值检查 |
| oci_spec | ⚠️ DIRECT_SINK | L512 | 污点指针控制写入目标地址 |
| oci_spec->process | 📌 USED | 调用方 | 新污点载体被调用方访问/修改 |

## 接收此污点的子函数
（无）

## 说明
- 函数确保 oci_spec->process 已被分配
- oci_spec->process 在 L512 赋值后成为新的污点载体
- 该字段后续被调用方访问和修改
- util_common_calloc_s 为标准内存分配函数，不列入跟入列表