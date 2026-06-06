# 污点流: vendor

## 污点源
- `vendor` (char **) 🔴 TAINTED — 输出参数，指向待写入 vendor 字符串的指针

## 新导入的污点对象
- `*vendor` 🔴 TAINTED — 由 L161 `*vendor = parts[0]` 写入，parts[0] 源自污点输入 kind 的分割子串

## 传播路径
```
### INPUT: vendor (char **) 🔴 TAINTED
├── [L152] vendor == NULL → 条件判断 (部分净化)
│   └── vendor 为 NULL 时提前返回 -1 (L153-155)
├── [L157] util_string_split_n(kind, '/', 2) → parts 🔴 TAINTED
│   └── kind 的污点通过字符串分割传播到 parts 数组
│   └── util_string_split_n 是外部库函数 🟡 EXPORT
├── [L158-160] 验证 parts 长度必须恰好为 2 → 条件分支
│   └── 验证失败时提前返回 -1
└── [L161] *vendor = parts[0] → *vendor 🔴 TAINTED (新导入的污点载体)
    └── **关键写入点**: parts[0] 源自污点输入 kind，*vendor 成为污点载体
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| (无) | — | — |

> 说明: `cdi_parser_parse_qualifier` 是叶函数，vendor 参数在函数体内未被作为参数传递给任何子函数。污点通过函数返回值 (0) 间接传递给调用者 `cdi_parser_parse_device`，调用者随后将 `*vendor` 传入 `validate_vendor_or_class_name(*vendor)` 进行验证。