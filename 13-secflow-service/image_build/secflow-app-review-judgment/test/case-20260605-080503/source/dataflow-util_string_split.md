# 数据流追踪: util_string_split

## 函数信息
- 文件: src/utils/cutils/utils_string.c
- 行号: L418-L460
- 签名: `char **util_string_split(const char *src_str, char _sep)`

## 数据流树状图

### INPUT-1: src_str (说明:) 🔴 TAINTED
├── [L430] if (src_str == NULL) → 安全检查，不传播
├── [L433] if (src_str[0] == '\0') → 条件判断，不传播
├── [L437] tmpstr = util_strdup_s(src_str) → tmpstr 🔴 TAINTED 🆕 新建污点载体
│   ├── [L439] str = tmpstr → str 🔴 TAINTED
│   │   └── [L440] token = strtok_r(str, deli, &reserve_ptr) → token 🔴 TAINTED（从污点字符串提取）
│   │       ├── [L441] util_grow_array(&res_array, &capacity, count+1, 16) → 扩展数组
│   │       └── [L445] res_array[count] = util_strdup_s(token) → res_array 🔴 TAINTED 🆕 新建污点载体
│   │           └── [L446] count++ → 内部计数
│   └── [L452] free(tmpstr) → 标准库释放
├── [L448] if (res_array == NULL) → make_empty_array() → 不含污点
├── [L453] return util_shrink_array(res_array, count + 1) → 📌 USED（返回给调用方）
└── [L457-L458] err_out: free(tmpstr) + util_free_array(res_array) → 📌 USED（错误路径清理）

## 污点终点汇总
| 脏数据 | 终点类型 | 位置 | 说明 |
|--------|---------|------|------|
| src_str | 📎 子函数 | L437 | util_strdup_s(src_str) 将污点复制到堆内存 |
| token | 📎 子函数 | L445 | util_strdup_s(token) 将污点 token 复制到数组 |
| res_array | 📎 子函数 | L453 | util_shrink_array 返回含污点字符串的数组 |
| res_array | 📎 子函数 | L458 | util_free_array 错误路径释放，防止泄漏 |