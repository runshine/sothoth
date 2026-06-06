# 污点流: util_string_split_n

## 污点源
- `说明:` (src) 🔴 TAINTED — 外部输入字符串参数

## 新导入的污点对象
- 无（函数内无 Recv/Read/Get/Decode/Parse 类调用写入输出对象）

## 传播路径
```
`说明:` (src) 🔴 TAINTED — 外部输入字符串
├── L387: str = util_strdup_s(`说明:`)  → str 🔴 TAINTED
│   └── L388: index = str               → index 🔴 TAINTED
│       ├── L390: token = strchr(index, sep)  → token 🔴 TAINTED
│       │   ├── L395: *token = '\0'     ⚠️ DIRECT_SINK (在污点控制位置写入截断符)
│       │   └── L396: util_array_append(&res_array, index)
│       │       └── index 🔴 TAINTED    → 📎 util_array_append
│       └── L398: index = token + 1     → index 🔴 TAINTED (指向下一段子串)
│           └── L390: token = strchr(index, sep)  → token 🔴 TAINTED (循环迭代)
│               └── L404: util_array_append(&res_array, index)
│                   └── index 🔴 TAINTED → 📎 util_array_append
└── L407: return res_array              → 📌 USED (数组含各污点子串)
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| util_array_append | L396, L404 | element (index) |