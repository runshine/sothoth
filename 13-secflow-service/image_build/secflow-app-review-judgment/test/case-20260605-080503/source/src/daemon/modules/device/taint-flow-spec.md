# 污点流: spec

## 污点源
- spec 🔴 TAINTED — OCI运行时规范结构体指针，由外部调用者(agent)传入，承载容器运行时配置、设备挂载点等运行时参数

## 新导入的污点对象
- 无 — 当前函数未调用Recv/Read/Get/Decode/Parse类函数

## 传播路径
```
spec (oci_runtime_spec*) 🔴 TAINTED
├── [L50] if (spec == NULL || ...) → 仅做NULL检查，不清洗内容
└── [L66] registry->ops->inject_devices(registry->cdi_cache, spec, devices)
    └── 📎 cdi_inject_devices(oci_spec)
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| cdi_inject_devices | L66 | oci_spec |