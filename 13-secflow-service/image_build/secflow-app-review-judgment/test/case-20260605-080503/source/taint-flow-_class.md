# 污点流: *class

## 污点源
- `*class` (const char *) 🔴 TAINTED — 外部输入，传入的类名字符串

## 新导入的污点对象
- 无

## 传播路径
```
### INPUT-1: *class (const char *) 🔴 TAINTED
└── [L207] validate_vendor_or_class_name(class) → 📎 见跟入列表
    └── [L212] return 0 → 📌 USED (函数返回验证状态码，干净)
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| static validate_vendor_or_class_name | L207 | name |

## 分析说明
`cdi_parser_validate_class_name` 是验证函数的包装器，将外部传入的 `*class` 指针直接传递给内部的 `static` 校验函数 `validate_vendor_or_class_name`，后者对字符进行白名单校验（首字符需为字母，尾字符需为字母或数字，中间字符可为字母数字下划线短横点）。该静态函数定义在本文件 L169，未导出，不进入跟入列表但应被系统递归分析。