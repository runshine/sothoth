# 污点流: device

## 污点源
- device 🔴 TAINTED — 外部输入的设备名字符串

## 新导入的污点对象
- `*name` 🔴 TAINTED — 由 `parts[1]` 在 L132 赋值写入输出参数
- `*vendor` 🔴 TAINTED — 由 `cdi_parser_parse_qualifier` 在 L134 间接触发
- `*class` 🔴 TAINTED — 由 `cdi_parser_parse_qualifier` 在 L134 间接触发

## 传播路径
```
device 🔴 TAINTED
└── [L127] util_string_split_n(device, '=', 2) → parts 🔴 TAINTED
    ├── parts[0] 🔴 TAINTED
    │   └── [L134] cdi_parser_parse_qualifier(parts[0], ...) → 📎 CALLEE
    └── parts[1] 🔴 TAINTED
        └── [L132] *name = parts[1] → *name 🔴 TAINTED (新导入)
            └── 📌 USED: 输出参数承载污点数据
        └── 引发的污点载体 (via L134):
            ├── *vendor 🔴 TAINTED (新导入)
            └── *class 🔴 TAINTED (新导入)
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| cdi_parser_parse_qualifier | L134 | parts[0] |