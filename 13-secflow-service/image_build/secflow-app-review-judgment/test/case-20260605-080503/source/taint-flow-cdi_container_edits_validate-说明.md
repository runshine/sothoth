# 污点流: 说明 (cdi_container_edits_validate)

## 污点源
- `说明:` e (cdi_container_edits *) 🔴 TAINTED — 外部 CDI 配置文件解析后的容器编辑对象

## 传播路径
```
### INPUT-1: e (cdi_container_edits *) 🔴 TAINTED
├── [L215] cdi_spec_get_edits(s) → edits 🔴 TAINTED
│   └── [L216] cdi_container_edits_validate(edits) → 🟡 EXPORT
└── [L112] cdi_device_get_edits(d) → edits 🔴 TAINTED
    └── [L116] cdi_container_edits_validate(edits) → 🟡 EXPORT
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| `cdi_container_edits_validate` | cdi_container_edits.h L31 | `e` (EXPORT) |