# 污点流: unresolved->items

## 污点源
- `parts` (= `unresolved->items` 强转) 🔴 TAINTED — 来自 CDI 缓存外部输入
- `len` (= `unresolved->len`) 🔴 TAINTED — 数组长度，同样为外部脏数据

## 新导入的污点对象
无 — `util_string_join` 是纯函数，无外部读取/Recv 模式，未通过输出参数导入新污点。

## 传播路径
```
parts (const char **) 🔴 TAINTED  ← 来自 unresolved->items
├── [L665] if (len == 0 || parts == NULL || sep == NULL) — NULL 守卫，parts 仍 🔴 TAINTED
├── [L671] len > SIZE_MAX/sep_len+1 — 溢出守卫，len 仍 🔴 TAINTED
├── [L672] result_len = (len - 1) * sep_len → result_len 🔴 TAINTED (由 tainted len 派生)
├── [L674] for (iter = 0; iter < len; iter++):
│   ├── [L676] if (parts[iter] == NULL ...) — 元素 NULL 检查
│   └── [L677] result_len += strlen(parts[iter]) → result_len 🔴 TAINTED (累加 tainted 字符串长度)
└── [L683] do_string_join(sep, parts, len, result_len)
    ⚠️ DIRECT_SINK [L645] util_smart_calloc_s(sizeof(char), result_len+1) — 分配大小受 tainted result_len 控制
    ⚠️ DIRECT_SINK [L649] for (iter=0; iter<parts_len-1; iter++) — 循环边界受 tainted len 控制
    ⚠️ DIRECT_SINK [L650–L651] strcat(res_string, parts[iter]) — tainted 字符串内容写入结果缓冲区

len (size_t) 🔴 TAINTED  ← 来自 unresolved->len
├── [L665] len == 0 — NULL 守卫，len 仍 🔴 TAINTED
├── [L671] len > SIZE_MAX/sep_len+1 — 溢出守卫，len 仍 🔴 TAINTED
├── [L672] result_len = (len - 1) * sep_len → result_len 🔴 TAINTED (tainted 算术)
├── [L674] for (iter = 0; iter < len; iter++) — 循环边界来自 tainted len ⚠️ DIRECT_SINK
│   └── [L677] result_len += strlen(parts[iter]) → result_len 🔴 TAINTED
└── [L683] do_string_join(..., len, ...) — 传入子函数
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| do_string_join | L683 | sep, parts, len, result_len |