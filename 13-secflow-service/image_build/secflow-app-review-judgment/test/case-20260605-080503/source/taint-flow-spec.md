# 污点流: spec

## 污点源
- spec 🔴 TAINTED

## 传播路径
```
spec → oci_spec (oci_runtime_spec*) 🔴 TAINTED
└── [L485] cdi_container_edits_apply(edits, oci_spec) 📌 USED
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| cdi_container_edits_apply | L485 | spec |