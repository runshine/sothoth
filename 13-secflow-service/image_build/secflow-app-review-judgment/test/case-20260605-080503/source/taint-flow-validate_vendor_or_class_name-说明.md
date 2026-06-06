# 污点流: name (validate_vendor_or_class_name)

## 污点源
- 参数: `name` (const char *) 🔴 TAINTED
- 来源: 外部调用者传入的脏数据（如配置文件/CDI 规范中的设备供应商/类名字段）

## 函数信息
- 文件: `src/daemon/modules/device/cdi/behavior/parser/cdi_parser.c`
- 行号: L168–L190（`validate_vendor_or_class_name`）
- 调用者: `cdi_parser_validate_vendor_name` (L198, vendor), `cdi_parser_validate_class_name` (L206, class)

## 当前函数内传播路径

### 直接使用（无派生变量，污点直接在字符级逐字节使用）

```
[INPUT-1] name (const char *) 🔴 TAINTED — 外部输入参数
├── [L173] if (name == NULL) → 空指针检查，不改变污点状态
├── [L176] if (!isalpha(name[0])) → name[0] 🔴 TAINTED（条件判断）
│   └── [L177] ERROR("...", name) → name 🔴 TAINTED 传入日志函数
│       └── 🟡 LOG — 标准库/日志函数，不记录
└── [L178] for (i = 1; name[i] != '\0'; i++)
    ├── [L179] isalnum(name[i]) → name[i] 🔴 TAINTED（逐字节输入）
    │   ├── L179: `!(isalnum(name[i]) || name[i] == '_' || ...)` 条件判断 ⚠️ DIRECT_SINK
    │   └── L180: ERROR("'%c' in name %s", name[i], name) → name[i] 传入日志
    │       └── 🟡 LOG — 标准库，不记录
    └── [L183] isalnum(name[i - 1]) → name[i-1] 🔴 TAINTED（循环结束后的尾字符检查）
        └── [L184] ERROR("...", name) → name 传入日志
            └── 🟡 LOG — 标准库，不记录
```

### 关键操作分析

| 行号 | 代码 | 操作类型 | 污点状态 | 说明 |
|------|------|---------|---------|------|
| L176 | `isalpha(name[0])` | 条件判断 | 🔴 TAINTED | 外部字符值参与条件判断 |
| L178 | `name[i]` 循环 | 逐字节访问 | 🔴 TAINTED | 循环体内每次都用脏字符调用 `isalnum` |
| L179 | `isalnum(name[i])` | 标准库函数调用 | 🔴 TAINTED | **⚠️ DIRECT_SINK**: `isalnum` 接收脏字符 |
| L183 | `isalnum(name[i - 1])` | 标准库函数调用 | 🔴 TAINTED | **⚠️ DIRECT_SINK**: 尾字符脏数据参与调用 |

### 新导入的污点载体
- 无 — 当前函数通过 `name` 参数接收字符数据并在函数内部逐字符验证，没有通过 `Recv/Read/Copy` 等调用导入新的污点载体。

## 接收此污点的子函数

| 函数 | 调用位置 | 接收的形参 |
|------|---------|-----------|
| `isalnum` | L179 | `name[i]` — 标准库函数，标记 🟡 EXPORT |
| `isalnum` | L183 | `name[i - 1]` — 标准库函数，标记 🟡 EXPORT |
| `ERROR` (日志) | L177/L180/L184 | `name`, `name[i]` — 仅日志，无数据写入 |

## 污点终点汇总

| 脏数据终点 | 终点类型 | 位置 | 说明 |
|-----------|---------|------|------|
| `isalnum(name[i])` | ⚠️ DIRECT_SINK | L179 | `name[i]` 为外部输入字节，负值 char 会导致 `isalnum` UB |
| `isalnum(name[i - 1])` | ⚠️ DIRECT_SINK | L183 | 尾字符字节参与 `isalnum`，负值 char 同上 |

## 关键 DIRECT_SINK 分析

**⚠️ DIRECT_SINK: `isalnum` 对有符号 char 的 UB 风险（L179, L183）**

`name` 参数为 `const char *`（在大多数平台 signed char），若外部输入包含非 ASCII 字符（如多字节 UTF-8 编码的中文字符），则在循环中 `name[i]` 会取到值 `>= 0x80` 的无符号字节，其在 signed char 下为**负值**，传入 `isalnum()` 将触发 **C 标准库未定义行为**（UB）。glibc 等实现依赖 `unsigned char` 转换或 locale 查找表，负值指针可能导致：
- 越界内存访问
- 绕过合法性检查继续执行

虽然 `isalnum` 返回值未被赋值给任何变量（仅作条件判断），但 UB 本身即为直接危险操作——在某些编译器/平台组合下，`isalnum` 内部可能通过指针运算读取超出预期的内存区域，泄露敏感数据或触发崩溃。

此风险不因"函数只做验证"而消除：UB 在 `isalnum()` 被调用的瞬间即已发生。

### 建议关注场景
若调用者传入的 `vendor`/`class` 字段包含非 ASCII 内容（来自 CDI 配置文件或用户输入），即触发此 DIRECT_SINK。