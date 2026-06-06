# 数据流追踪: util_strdup_s

## 函数信息
- 文件: src/utils/cutils/utils.c
- 行号: L295-L311
- 签名: `char *util_strdup_s(const char *src)`
- 声明: src/utils/cutils/utils.h L340

> ⚠️ 注意：任务描述中该参数名为 `src_str`，但函数实际形参名为 `src`。本报告以函数实际形参 `src` 为追踪对象。

---

## 数据流树状图

### INPUT-1: src (const char *) 🔴 TAINTED
├── [L299] `if (src == NULL)` → 条件判断，无数据传播
│   └── [L300] `return NULL;` → 提前返回 NULL（无污点数据流出）
└── [L303] `dst = strdup(src);` → `src` 🔴 TAINTED 传入 stdlib strdup
    └── `dst` ← **🔴 TAINTED** （新引入的污点载体，由 strdup 分配并拷贝污点数据）
        ├── [L304] `if (dst == NULL)` → NULL 检查，无数据传播
        │   └── [L305] `abort();` → OOM 时异常终止
        └── [L308] `return dst;` → 📌 USED（污点字符串的副本被返回给调用者）

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| src | strdup (stdlib) | L303 | 标准库函数，已分配内存并拷贝污点数据 |
| dst (新载体) | return | L308 | strdup 生成的污点字符串副本返回给调用者 |

---

## 传播路径说明

1. **L299–L300**: `src` 接受 NULL 检查，外部污点传入后直接进行空指针判断，不产生新的污点变量。
2. **L303**: `strdup(src)` — 标准库函数，将 `src` 指向的污点字符串复制到新分配的堆内存中。
   - `strdup` 是标准C库函数，按规则标记为 `🟡 EXPORT`
   - 其返回值赋给 `dst`，使 `dst` 成为新的 🔴 TAINTED 载体
3. **L304–L305**: `dst == NULL` 检查，OOM 时调用 `abort()`，属于错误处理路径，不构成污点传播。
4. **L308**: `return dst` — `dst` 承载污点数据被返回给调用者，函数终点。

---

## 子函数跟入列表

| 文件 | 函数 | 行号 | 接收参数 | 说明 |
|------|------|------|----------|------|
| — | strdup (stdlib) | L303 | src | 🟡 EXPORT — 标准库函数，跟入规则豁免 |