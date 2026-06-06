# 污点流: path

## 污点源
- `path` (const char *) 🔴 TAINTED — 调用者传入的外部输入参数

## 新导入的污点对象
- 无

## 传播路径

```
### INPUT-1: path (const char *) 🔴 TAINTED
├── [L53] if (path == NULL) → 条件判断，path 未被清洗，污点保留
└── [L57] nret = stat(path, &s) ⚠️ DIRECT_SINK: path 直接作为文件系统路径参数
    ├── [L58] if (nret < 0) → 返回值检查，控制流分支，不影响污点
    └── [L62] return S_ISDIR(s.st_mode) → 📌 USED
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| 无 | — | — |