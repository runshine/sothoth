# 数据流追踪: `util_string_split` — 参数 `说明:`

## 函数信息
- 文件: `src/utils/cutils/utils_string.c`
- 行号: L418-L460
- 签名: `char **util_string_split(const char *src_str, char _sep)`

## 污点源

**[INPUT-1] `说明:` (即 `src_str`) 🔴 TAINTED**
- 外部输入参数，来源由调用方控制

---

## 逐行污点传播追踪

### L418-L419: 入口 + 局部变量声明
```c
char **util_string_split(const char *src_str, char _sep)
{
    char *token = NULL;
    char *str = NULL;
    char *tmpstr = NULL;
    char *reserve_ptr = NULL;
    char deli[2] = { _sep, '\0' };
    char **res_array = NULL;
    size_t capacity = 0;
    size_t count = 0;
    int ret, tmp_errno;
```
- `src_str` 接收外部污点数据 → 标记为 🔴 TAINTED
- `res_array` 初始为 NULL，尚未被污点数据污染

---

### L428: NULL 检查
```c
    if (src_str == NULL) {
        return NULL;
    }
```
- 仅做安全检查，不影响污点状态

---

### L430-L431: 空字符串检查
```c
    if (src_str[0] == '\0') {
        return make_empty_array();
    }
```
- `src_str[0]` 读取污点数据用于条件判断 → 仍 🔴 TAINTED（但仅作判断，未传播）

---

### L433: `util_strdup_s` 复制污点字符串 🆕 新建污点载体
```c
    tmpstr = util_strdup_s(src_str);
```
- `src_str` 作为参数传入 `util_strdup_s` → 📎 子函数调用
- `util_strdup_s` 内部执行 `strdup(src_str)`，将污点数据复制到新分配的堆内存
- **结果**：`tmpstr` 承载了污点数据的副本 → 🔴 TAINTED
- `res_array` 仍为 NULL，尚未被污染

---

### L435: 初始化遍历指针
```c
    str = tmpstr;
```
- `str` 指向 `tmpstr`（已污染）→ 🔴 TAINTED
- 后续 `strtok_r` 将基于此污点字符串进行分割

---

### L436-L449: 循环遍历分割
```c
    for (; (token = strtok_r(str, deli, &reserve_ptr)); str = NULL) {
        ret = util_grow_array(&res_array, &capacity, count + 1, 16);
        if (ret < 0) {
            goto err_out;
        }
        res_array[count] = util_strdup_s(token);
        count++;
    }
```
- **L436** `strtok_r(str, deli, &reserve_ptr)` — 标准库函数，从污点字符串 `str` 中提取子串
  - `str` 🔴 TAINTED → `token` 🔴 TAINTED（基于污点数据的提取结果）
- **L437** `util_grow_array(&res_array, &capacity, count + 1, 16)` — 扩展数组容量
  - `res_array` 此时仍为 NULL 或含部分 token，为数组载体
  - 参数 `count + 1` 为内部计数，非污点来源 → 不记录
- **L440** `res_array[count] = util_strdup_s(token)` — 将污点 token 复制存入数组
  - `token` 🔴 TAINTED → `util_strdup_s` → 📎 子函数
  - **`res_array[count]`** 写入污点数据 → `res_array` 整体 🔴 TAINTED
- **L441** `count++` → 内部计数变量，不携带污点

---

### L451-L452: 循环结束后再次检查
```c
    if (res_array == NULL) {
        free(tmpstr);
        return make_empty_array();
    }
```
- `res_array` 此时已包含污点 token → 条件不满足，不走此分支

---

### L453: 释放临时字符串 + 返回
```c
    free(tmpstr);
    return util_shrink_array(res_array, count + 1);
```
- **L453** `free(tmpstr)` — 释放中间污点载体 `tmpstr`，无传播
- **L454** `util_shrink_array(res_array, count + 1)` — 收缩数组并返回
  - `res_array` 🔴 TAINTED → 整体承载污点 token 数组
  - → 📎 子函数调用（返回给调用方）

---

### L456-L460: 错误处理路径 (err_out label)
```c
err_out:
    tmp_errno = errno;
    free(tmpstr);
    util_free_array(res_array);
    errno = tmp_errno;
    return NULL;
```
- `tmpstr` 🔴 TAINTED → `free(tmpstr)` — 标准库释放，无传播
- `res_array` 🔴 TAINTED → `util_free_array(res_array)` — 📎 子函数调用（正确释放污点数组）

---

## 数据流树状图

```
### INPUT-1: src_str (说明:) 🔴 TAINTED
├── [L430] if (src_str[0] == '\0') → 条件判断，不传播
├── [L433] tmpstr = util_strdup_s(src_str) → tmpstr 🔴 TAINTED 🆕 新建污点载体
│   ├── [L435] str = tmpstr → str 🔴 TAINTED
│   │   └── [L436] token = strtok_r(str, deli, &reserve_ptr) → token 🔴 TAINTED
│   │       └── [L440] res_array[count] = util_strdup_s(token) → res_array 🔴 TAINTED 🆕 新建污点载体
│   │           └── [L437] util_grow_array(&res_array, ...) → 📎 子函数
│   │           └── [L454] util_shrink_array(res_array, ...) → 📎 子函数
│   └── [L453] free(tmpstr) → 标准库释放
└── [L458] util_free_array(res_array) → 📎 子函数
```

---

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `说明:` (src_str) | `util_strdup_s(src_str)` | L437 | 将污点字符串复制到堆内存 |
| `token` (derived from src_str) | `util_strdup_s(token)` | L440 | 将分割出的污点 token 复制到数组 |
| `res_array` (含污点 token) | `util_shrink_array(res_array, ...)` | L454 | 返回给调用方，污点数据传播至外部 |
| `res_array` (含污点 token) | `util_free_array(res_array)` | L458 | 错误路径释放，防止泄漏 |
| `tmpstr` | `free(tmpstr)` | L453 | 标准库释放，无传播 |