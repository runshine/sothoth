## Upstream Entry Hints


| Taint | Upstream Hint | source_kind | source | Consumed By |
|---|---|---|---|---|
| `ip_header` | 上游未提供额外说明 | - | missing | worker_prompt, taint_prompt |

---
# 数据流追踪: IPSEC_LIB_Ipv4AddrToStr

## 函数信息
- **文件**: `core/ipsec/libipsec.c`
- **行号**: L7682–L7697
- **签名**: `int64_t IPSEC_LIB_Ipv4AddrToStr(int64_t addr, int64_t out_str, int out_len)`

## 污点源
| 变量 | 类型 | 说明 |
|------|------|------|
| `ip_header` | 🔴 TAINTED | 网络数据包缓冲区， callers 通过 `RAW_U32(ip_header, 12/16)` 提取 IPv4 源/目的地址字段后作为 `addr` 参数传入 |
| `addr` | 🔴 TAINTED | 形参， callers 传入的 `RAW_U32(ip_header, 12)` 或 `RAW_U32(ip_header, 16)` 的结果 |

## 新导入的污点对象
| 变量 | 类型 | 说明 |
|------|------|------|
| `ipv4` | 🔴 TAINTED | L7684 由 `addr` 直接赋值，继承污点 |
| `result` | 🔴 TAINTED | L7685 由 `addr` 直接赋值，继承污点 |
| `out_str` | 🔴 TAINTED carrier | 形参，作为输出缓冲区传入 callers 的 `src_addr_text`/`dst_addr_text`，由 `VOS_IpAddrToStr` 写入格式化的 IP 字符串后承载污点数据 |

## 传播路径

```
### INPUT-1: addr (int64_t) 🔴 TAINTED
├── [L7684] ipv4 = (unsigned int)addr → ipv4 🔴 TAINTED
├── [L7685] result = addr → result 🔴 TAINTED
├── [L7686] if (out_len != 0)
│   ├── [L7687] if (out_str == 0)
│   │   └── [L7689] return result → 🟢 CLEANED (整型状态码)
│   └── [L7690] return VOS_IpAddrToStr(__builtin_bswap32(ipv4), out_str)
│               ├─ ipv4 🔴 TAINTED → VOS_IpAddrToStr 第1参数
│               └─ out_str 🔴 TAINTED carrier → VOS_IpAddrToStr 第2参数
│                   📎 见跟入列表 (VOS_IpAddrToStr)
└── [L7692] result = VRP_Assert(...) → result 🟢 CLEANED (assert 返回值)
    ├── [L7693] if (out_str != 0)
    │   └── [L7695] return VOS_IpAddrToStr(__builtin_bswap32(ipv4), out_str)
    │               ├─ ipv4 🔴 TAINTED → VOS_IpAddrToStr 第1参数
    │               └─ out_str 🔴 TAINTED carrier → VOS_IpAddrToStr 第2参数
    │                   📎 见跟入列表 (VOS_IpAddrToStr)
    └── [L7696] return result → 🟢 CLEANED
```

## ⚠️ DIRECT_SINK（直接危险操作）

| 位置 | 操作 | 风险描述 |
|------|------|----------|
| L6206/6207, L6767/6768, L8811/8812 | `RAW_U32((void *)ip_header, 12/16)` | 从网络包缓冲区在固定结构偏移量处读取 4 字节 IPv4 地址；若 `ip_header` 未做包长度边界校验，可能越界读取超过实际包数据长度 |
| L9860/9861, L11249/11250 | `RAW_U32(ip_header, 12/16)` | 同上，读取源/目的 IPv4 地址 |

> 注：偏移量 12/16 是编译时常量（IPv4 头结构中 SrcAddr/DstAddr 的固定位置），指针运算本身未受污点控制；残余风险为 `ip_header` 基指针在调用前未充分校验包实际长度。

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `addr` / `ipv4` | `VOS_IpAddrToStr` | L7690, L7695 | 经字节序转换后作为 IP 地址参数，外部库处理 |
| `out_str` | `VOS_IpAddrToStr` | L7690, L7695 | 作为输出缓冲区，函数向其写入格式化 IP 字符串 |
| `result` | return | L7689, L7696 | 整型状态码，🟢 CLEANED |

## 跟入列表（子函数）

| 文件 | 函数 | 调用行 | 接收的形参 |
|------|------|--------|------------|
| - | `VOS_IpAddrToStr` | L7690, L7695 | `__builtin_bswap32(ipv4)`, `out_str` |

> `VOS_IpAddrToStr` 为外部库函数（标记 🟡 EXPORT）。