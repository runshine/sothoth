# 污点流: format_errorf

## 污点源
- `...` (variadic args) 🔴 TAINTED — 外部调用者传入的可变参数

## 新导入的污点对象
- `errbuf` 🔴 TAINTED — 由 `vsnprintf` 在 L68 将 variadic args 格式化后写入

## 传播路径
```
variadic args (...) 🔴 TAINTED
├── [L67] va_start(argp, format)
├── [L68] vsnprintf(errbuf, BUFSIZ, format, argp) → errbuf 🔴 TAINTED
│   └── [L74] *err = util_strdup_s(errbuf)
│       └── *err 🔴 TAINTED (输出参数承载污点)
└── [L74] 📌 USED — *err 输出参数
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| vsnprintf | L68 | argp (含污点) |
| util_strdup_s | L74 | errbuf |