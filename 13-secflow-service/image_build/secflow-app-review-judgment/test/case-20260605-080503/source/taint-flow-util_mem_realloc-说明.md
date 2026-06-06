# 数据流追踪: util_mem_realloc — 参数 `newsize`

## 函数信息
- 文件: src/utils/cutils/utils.c
- 行号: L83-L97
- 签名: `int util_mem_realloc(void **newptr, size_t newsize, void *oldptr, size_t oldsize)`

## 污点源

| ID | 参数 | 类型 | 说明 |
|----|------|------|------|
| INPUT-1 | `newsize` | `size_t` | 🔴 TAINTED — 外部调用者传入的大小参数，来源可能是配置解析/用户输入 |

## 数据流树状图

### INPUT-1: newsize (size_t) 🔴 TAINTED
├── [L87] `if (newptr == NULL || newsize == 0)` → 仅零值检查，内容未清洗
├── [L91] `util_common_calloc_s(newsize)` ⚠️ DIRECT_SINK
│   └── **newsize 直接控制内存分配大小，若为极大值可能导致 OOM/DoS**
└── [L94] `(newsize < oldsize) ? newsize : oldsize` → ⚠️ DIRECT_SINK
    └── **newsize 参与三元运算，决定 memcpy 复制字节数**
        ├── newsize < oldsize → 复制 newsize 字节（受污点控制）
        └── newsize >= oldsize → 复制 oldsize 字节（受oldsize约束）

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `newsize` | ⚠️ DIRECT_SINK: `util_common_calloc_s(newsize)` | L91 | 污点大小值直接控制内存分配，若传入极大值可导致 OOM/DoS |
| `newsize` | ⚠️ DIRECT_SINK: `memcpy(tmp, oldptr, (newsize < oldsize) ? newsize : oldsize)` | L94 | 污点 newsize 参与三元运算，控制 memcpy 复制字节数 |

## 关键危险分析

### 1. util_common_calloc_s(newsize) 分配大小受污点控制 (L91)
`newsize` 由外部调用者传入，未在本函数内验证合法性（仅检查 `!= 0`）。若污点值为极大值（如接近 SIZE_MAX），在受限容器环境中可能导致：
- 系统内存耗尽（OOM）
- 分配失败，但错误路径可能影响后续逻辑

### 2. memcpy 复制大小受污点控制 (L94)
污点 `newsize` 参与三元表达式 `(newsize < oldsize) ? newsize : oldsize`。若污点值小于 `oldsize`，则 `memcpy` 的第三个参数为 `newsize`（受污点控制），可能引发非预期内存访问。

## 子函数跟入列表

| 文件 | 函数 | 行号 | 污点实参 |
|------|------|------|----------|
| src/utils/cutils/utils.c | `util_common_calloc_s` | L286 | `size`（即 newsize） |