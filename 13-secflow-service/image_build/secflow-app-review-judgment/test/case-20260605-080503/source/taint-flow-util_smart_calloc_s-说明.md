# 污点流: `说明:` = unit_size (第一个参数) — util_smart_calloc_s

## 函数信息
- 文件: src/utils/cutils/utils.c
- 行号: L267-L287
- 签名: `void* util_smart_calloc_s(size_t unit_size, size_t count)`
- 分析参数: `说明:` → `unit_size` (size_t, 第一个参数) 🔴 TAINTED

---

## 传播路径追踪

### INPUT-1: unit_size (size_t) 🔴 TAINTED — 外部输入参数
├── [L269] if (unit_size == 0) → return NULL（安全路径）
│   └── unit_size 参与零值检查，非危险操作
└── [L273] if (count > (MAX_MEMORY_SIZE / unit_size)) → return NULL（安全路径）
    └── unit_size 作为除数参与整数溢出防护检查
    └── 真 → return NULL（安全路径）
    └── 假 → 继续执行
        └── [L286] calloc(count, unit_size) → 🟡 EXPORT (标准C库函数)

---

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| unit_size | calloc | L286 | 标准C库函数，标记EXPORT |

---

## 子函数调用（跟入列表）
| 文件 | 函数 | 行号 | 接收参数 | 说明 |
|------|------|------|----------|------|
| - | calloc | L286 | count, unit_size | 标准C库函数 🟡 EXPORT |

---

## 安全机制评估
- [L269] unit_size == 0 检查 → 真时返回NULL（安全路径）
- [L273] 整数溢出检查: count > (MAX_MEMORY_SIZE / unit_size) → 真时返回NULL（安全路径）

⚠️ **DIRECT_SINK 评估**:
- L273 中 `unit_size` 作为除数，若 unit_size=0 会触发除零错误，但 L269 已做零值检查
- L286 中 `unit_size` 传递给 calloc 的 nmemb 参数，若 unit_size 极大可能导致分配巨大内存
- 综合评估: 存在潜在整数溢出风险，但函数内部有防御性检查

---

## 新导入的污点载体
无新导入的污点对象（calloc 为标准C库函数）

---

## 备注
- `unit_size` 在函数内部仅参与比较运算和 calloc 参数传递
- 函数本身包含防御性检查，污点数据未直接导致危险操作
- calloc 为标准C库函数，污点数据传递到此为止# util_smart_calloc_s - 无需跟入的子函数 (calloc 为标准C库函数)

tainted.list 无条目 - util_smart_calloc_s 唯一的子函数 calloc 为标准C库函数，标记为 EXPORT，无需递归分析
