# 污点流: oci_spec

## 污点源
- oci_spec (oci_runtime_spec*) 🔴 TAINTED

## 新导入的污点对象
- oci_spec->process 🔴 TAINTED — 由 `make_sure_oci_spec_process` 在 L512 赋值创建

## 传播路径
```
oci_spec (oci_runtime_spec*) 🔴 TAINTED
├── [L510] oci_spec->process == NULL
│   └── ⚠️ DIRECT_SINK: 污点指针解引用，访问process字段
├── [L512] oci_spec->process = util_common_calloc_s(sizeof(defs_process))
│   └── ⚠️ DIRECT_SINK: 污点指针控制写入目标
│       └── oci_spec->process 🔴 TAINTED (新污点载体)
└── [L518] return 0
    └── 🟢 CLEANED (返回状态码)
```

## DIRECT_SINK 标注
| 行号 | 危险操作 | 描述 |
|------|---------|------|
| L510 | oci_spec->process == NULL | 污点指针解引用访问process字段 |
| L512 | oci_spec->process = ... | 污点指针oci_spec控制process字段的写入目标 |

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| (无) | - | - |

## 说明
- 函数确保 oci_spec->process 已被分配
- oci_spec->process 在 L512 赋值后成为新的污点载体
- 该字段后续被调用方访问和修改
- util_common_calloc_s 为标准内存分配函数，不列入跟入列表