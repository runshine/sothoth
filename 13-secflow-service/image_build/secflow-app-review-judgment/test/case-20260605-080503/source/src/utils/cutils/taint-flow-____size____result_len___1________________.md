# 污点流: 说明: size (= result_len + 1) — 分配大小受 说明: 影响

## 污点源
- `count` (size (= result_len + 1)) 🔴 TAINTED — 调用方将 `result_len + 1` 作为 `count` 形参传入

## 新导入的污点对象
- （无 — 本函数未调用 Recv/Read/Get/Decode/Parse 类函数）

## 传播路径
```
### INPUT: count (size_t) 🔴 TAINTED
├── [L273] if (count > (MAX_MEMORY_SIZE / unit_size))
│   ├── 条件为真 → [L274] return NULL
│   └── 条件为假 → count 🔴 TAINTED 穿透检查
└── [L284] return calloc(count, unit_size) → ⚠️ DIRECT_SINK
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| （无子函数） | — | — |

> `calloc` 为标准 C 库函数，规则禁止加入跟入列表，直接标记为 🟡 EXPORT