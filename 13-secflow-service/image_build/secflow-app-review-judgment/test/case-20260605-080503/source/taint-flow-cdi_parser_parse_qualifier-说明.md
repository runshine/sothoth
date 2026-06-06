# 数据流追踪: cdi_parser_parse_qualifier (参数: vendor)

## 函数信息
- 文件: src/daemon/modules/device/cdi/behavior/parser/cdi_parser.c
- 行号: L148-L166
- 签名: `int cdi_parser_parse_qualifier(const char *kind, char **vendor, char **class)`

## 数据流树状图

### INPUT-1: vendor (char **) 🔴 TAINTED (output carrier)
├── [L152] vendor == NULL → 条件判断 (部分净化)
│   └── vendor 为 NULL 时提前返回 -1 (L153-155)
├── [L157] util_string_split_n(kind, '/', 2) → parts 🔴 TAINTED
│   └── kind 的污点通过字符串分割传播到 parts 数组
│   └── util_string_split_n 是外部库函数 🟡 EXPORT
├── [L158-160] 验证 parts 长度必须恰好为 2 → 条件分支
│   └── 验证失败时提前返回 -1
└── [L161] `*vendor = parts[0]` → *vendor 🔴 TAINTED (新导入的污点载体)
    └── **关键污点写入**: 污点子串 parts[0] 被写入输出参数 *vendor
    └── vendor 指针本身不参与运算，但其指向的字符串现在携带污点

## 污点终点汇总
| 脏数据 | 终点类型 | 位置 | 说明 |
|--------|---------|------|------|
| vendor | 📌 USED | L161 | 输出参数 *vendor 被写入 parts[0]（从 kind 分割得到的污点子串），成为污点载体 |

## 详细行级追踪

| 行号 | 代码 | 分析 |
|------|------|------|
| L148 | `int cdi_parser_parse_qualifier(const char *kind, char **vendor, char **class)` | 函数签名: vendor 是 char** 类型输出参数 |
| L150 | `__isula_auto_array_t char **parts = NULL;` | 局部变量初始化，与 vendor 无直接关联 |
| L152 | `if (kind == NULL \|\| vendor == NULL \|\| class == NULL)` | vendor 参与 NULL 检查。属于条件判断/部分净化 — vendor 为 NULL 时函数提前返回 -1 |
| L157 | `parts = util_string_split_n(kind, '/', 2);` | kind 的污点通过字符串分割传播到 parts 数组。util_string_split_n 是标准工具函数 🟡 EXPORT |
| L158-160 | `if (parts == NULL \|\| util_array_len(...) != 2 \|\| parts[0] == NULL \|\| parts[1] == NULL)` | 验证分割结果有效性。若不满足 (必须恰好 2 部分)，函数提前返回 -1。vendor 不参与此判断 |
| L161 | `*vendor = parts[0];` | **新污点载体导入**: parts[0] 源自污点输入 kind，*vendor 被写入该值。vendor 指针本身成为污点载体，携带解析后的 vendor 字符串 |
| L162 | `parts[0] = NULL;` | 内存清理 (防止 auto_array 析构时重复释放)，与 vendor 的数据流追踪无关 |
| L163 | `*class = parts[1];` | vendor 不参与。class 输出参数获得 parts[1] |
| L164 | `parts[1] = NULL;` | 内存清理 |
| L166 | `return 0;` | 成功状态码，无污点 |

## 关键发现

1. **vendor 作为输出参数**: vendor (char**) 本身是指针，其指向的 char* 才是数据载体。函数体内 vendor 指针不参与运算，只在 L161 处被dereference 写入污点数据。

2. **新污点载体 *vendor**: 在 L161 行，`*vendor = parts[0]` 将污点字符串写入 *vendor。从 kind 分割得到的子串 parts[0] 继承 kind 的污点属性，因此 *vendor 成为新的 🔴 TAINTED 载体。

3. **无 DIRECT_SINK**: 函数体内没有 memcpy/strcpy/sprintf 等危险操作，vendor 数值未参与指针运算或数组下标操作。

4. **叶函数**: cdi_parser_parse_qualifier 内部没有调用任何子函数，vendor 未作为参数传入任何子函数。污点通过函数返回值 (0) 间接传递给调用者。

5. **调用者侧污点传播**: 函数返回后，调用者 (cdi_parser_parse_device) 获得被污染的 *vendor，该值随后作为参数传入 `validate_vendor_or_class_name(*vendor)` 进行验证。