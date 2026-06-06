# 污点流: `说明:` (src_str)

## 污点源
- `说明:` (src_str) 🔴 TAINTED — 外部输入参数

## 新导入的污点对象
- `tmpstr` 🔴 TAINTED — 由 `util_strdup_s(src_str)` 在 L437 写入
- `res_array` 🔴 TAINTED — 由 `res_array[count] = util_strdup_s(token)` 在 L445 写入

## 传播路径

```
### INPUT: src_str 🔴 TAINTED
├── [L437] tmpstr = util_strdup_s(src_str) → tmpstr 🔴 TAINTED 🆕
│   ├── [L439] str = tmpstr → str 🔴 TAINTED
│   │   └── [L440] token = strtok_r(str, deli, &reserve_ptr) → token 🔴 TAINTED
│   │       └── [L445] res_array[count] = util_strdup_s(token) → res_array 🔴 TAINTED 🆕
│   └── [L452] free(tmpstr) → 标准库释放
├── [L453] util_shrink_array(res_array, count + 1) → 📌 返回给调用方
└── [L458] util_free_array(res_array) → 错误路径释放
```

## 接收此污点的子函数

| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| `util_strdup_s` | L437 | `src_str` |
| `util_strdup_s` | L445 | `token` |
| `util_shrink_array` | L453 | `res_array` |
| `util_free_array` | L458 | `res_array` |

> `strtok_r` 为标准 C 库函数，`free` 为标准库释放函数，不列入跟入列表。