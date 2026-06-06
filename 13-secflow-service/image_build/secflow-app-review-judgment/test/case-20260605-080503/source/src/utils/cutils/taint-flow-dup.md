# 污点流: dup

## 污点源
- dup 🔴 TAINTED

## 新导入的污点对象
- 无（函数不调用 Recv/Read/Get 等导入外部数据的函数）

## 传播路径

### INPUT-1: dup (char*) 🔴 TAINTED — 局部变量

---

### 函数: util_parse_byte_size_string (L243–L273)

├── [L246] `char *dup = NULL` → 局部变量声明
├── [L253] `dup = util_strdup_s(s)` → dup 🔴 TAINTED
│   └── s 为外部输入字符串，util_strdup_s 创建副本，dup 继承污点
├── [L254] `if (dup == NULL)` → 清洁空检查，污点保持
├── [L258] `pmlt = dup` → pmlt 🔴 TAINTED
│   └── 指针直接赋值，pmlt 指向与 dup 相同的污点数据
├── [L265] `free(dup)` → dup 释放，但 pmlt 仍持有指向已释放堆内存的指针
├── [L271] `util_parse_size_int_and_float(dup, mltpl, converted)` 📎 子函数
│   └── dup 作为第一个实参传入
└── [L272] `free(dup)` → ⚠️ 双重释放风险（dup 已在 L265 释放）

---

### 函数: util_parse_percent_string (L278–L297)

├── [L278] `char *dup = NULL` → 局部变量声明
├── [L284] `dup = util_strdup_s(s)` → dup 🔴 TAINTED
│   └── s 为外部输入字符串，dup 继承污点
├── [L285] `if (dup == NULL)` → 清洁空检查，污点保持
├── [L288] `dup[strlen(dup) - 1] = 0` → ⚠️ DIRECT_SINK: 污点长度驱动数组写入
│   └── strlen(dup) 由污点内容决定；空串时 strlen("")-1 = -1 整型下溢
├── [L290] `*converted = strtol(dup, NULL, 10)` 📎 子函数
│   └── dup 作为源字符串传入 strtol
├── [L293] `free(dup)` → dup 释放
└── [L297] `free(dup)` → ⚠️ 双重释放风险（若 L293 已释放则危险）

## 接收此污点的子函数

| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| util_parse_size_int_and_float | L271 | dup |
| strtol | L290 | dup (源字符串) |