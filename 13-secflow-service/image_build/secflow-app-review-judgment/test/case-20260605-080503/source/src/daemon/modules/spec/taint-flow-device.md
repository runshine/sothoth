# 污点流: device

## 污点源
- `device` (defs_device_cgroup*) 🔴 TAINTED — 局部变量，字段由外部输入参数直接填充

## 新导入的污点对象
- 无（函数内无 Recv/Read/Get/Fetch/Decode/Parse 模式直接写入输出对象）

## 传播路径

### device (defs_device_cgroup*) 🔴 TAINTED carrier
├── [L2739] `device = util_common_calloc_s(sizeof(*device))` → device 分配
├── [L2745] `device->allow = allow` → device->allow 🔴 TAINTED（来自外部 param）
├── [L2746] `device->type = util_strdup_s(dev_type)` → device->type 🔴 TAINTED（外部字符串复制）
├── [L2747] `device->access = util_strdup_s(access)` → device->access 🔴 TAINTED（外部字符串复制）
├── [L2748] `device->major = major` → device->major 🔴 TAINTED（外部数值）
├── [L2749] `device->minor = minor` → device->minor 🔴 TAINTED（外部数值）
│
├── [L2742] `make_sure_oci_spec_linux_resources(oci_spec)` → 🟢 CLEANED（仅初始化，device 未传入）
├── [L2752] `util_mem_realloc(...)` → 🟡 EXPORT（标准 realloc，作用对象为 oci_spec->linux->resources->devices 数组指针）
├── [L2762] `free_defs_device_cgroup(device)` → 仅错误路径，标准 free
│
└── [L2760] `oci_spec->linux->resources->devices[oci_spec->linux->resources->devices_len] = device`
    └── 📌 USED — 污染的 device 指针被写入 oci_spec（输出参数）的设备数组

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| （无） | — | — |

> **说明**: `device` 作为局部变量由外部参数（dev_type、access、major、minor）填充而成为污点载体。所有调用的子函数（make_sure_oci_spec_linux_resources、util_mem_realloc、free_defs_device_cgroup）均不直接接收 `device` 作为实参，故无跟入记录。