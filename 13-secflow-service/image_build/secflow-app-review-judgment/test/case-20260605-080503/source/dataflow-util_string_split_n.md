# 数据流追踪: util_string_split_n

## 函数信息
- 文件: src/utils/cutils/utils_string.c
- 行号: L375-L420
- 签名: `char **util_string_split_n(const char *src, char sep, size_t n)`

## 数据流树状图

### INPUT-1: src (const char *) 🔴 TAINTED
├── [L381] if (src == NULL) return 0 → 📌 USED (仅条件比较)
├── [L386] str = util_strdup_s(src) → str 🔴 TAINTED
├── [L387] index = str → index 🔴 TAINTED
│   └── [L389] for(token = strchr(index, sep); token != NULL; ...) → token 🔴 TAINTED
│       ├── [L395] *token = '\0' ⚠️ DIRECT_SINK (在污点控制位置写入截断符)
│       └── [L396] util_array_append(&res_array, index) → 📎 util_array_append
│           index 🔴 TAINTED → res_array[] 🔴 TAINTED
├── [L398] index = token + 1 → index 🔴 TAINTED
│   └── [L399] token = strchr(index, sep) → token 🔴 TAINTED (循环迭代)
│       ├── [L395] *token = '\0' ⚠️ DIRECT_SINK (在污点控制位置写入截断符)
│       └── [L404] util_array_append(&res_array, index) → 📎 util_array_append
│           index 🔴 TAINTED → res_array[] 🔴 TAINTED
└── [L407] return res_array → 📌 USED (数组含各污点子串)

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| src | 📌 USED | L407 | 作为返回值数组元素返回 |
| str | DIRECT_SINK | L395 | 在污点控制位置写入截断符 '\0' |

## 新导入的污点载体
- 无（函数内无 Recv/Read/Get/Decode/Parse 类调用写入输出对象）