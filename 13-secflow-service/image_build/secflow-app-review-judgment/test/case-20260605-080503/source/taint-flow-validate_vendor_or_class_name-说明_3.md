# 污点流: validate_vendor_or_class_name(name)

## 函数信息
- **文件:** `src/daemon/modules/device/cdi/behavior/parser/cdi_parser.c`
- **行号:** L169–L195
- **签名:** `static int validate_vendor_or_class_name(const char *name)`

## 污点源
- `name` (const char*) 🔴 TAINTED — 外部 CDI 配置输入的 vendor/class 名称

## 新导入的污点对象
**无** — 本函数内无任何输出参数、缓冲区或消息对象接收脏数据写入

## 传播路径

```
### INPUT-1: name (const char*) 🔴 TAINTED — 外部 CDI 配置输入
├── [L171] if (name == NULL) → 空指针检查
│   └── [L172] ERROR("Empty name") → 无脏数据参数
│       └── [L173] return -1 → 错误码返回，干净
├── [L175] if (!isalpha(name[0])) → name[0] 读取后传入 isalpha → 🟡 EXPORT stdlib
│   ├── [L176] ERROR("%s, should start with letter", name) → name 传入日志 → 🟡 EXPORT logging
│   │   └── [L177] return -1 → 错误码返回，干净
│   └── [L178] return 0 → 验证通过（首字符合法）
└── [L179] for (i=1; name[i]!='\0'; i++) → 循环遍历脏字符数组
    ├── [L181] if (!(isalnum(name[i]) || name[i]=='_'|'-'|'.')) → name[i] 读取后传入 isalnum → 🟡 EXPORT stdlib
    │   ├── [L182] ERROR("Invalid char '%c' in name %s", name[i], name) → name[i]+name 传入日志 → 🟡 EXPORT logging
    │   │   └── [L183] return -1 → 错误码返回，干净
    │   └── [L184] continue → 继续循环
    └── [L186] if (!isalnum(name[i-1])) → name[i-1] 读取后传入 isalnum → 🟡 EXPORT stdlib
        ├── [L187] ERROR("...should end with letter or digit", name) → name 传入日志 → 🟡 EXPORT logging
        │   └── [L188] return -1 → 错误码返回，干净
        └── [L189] return 0 → 验证通过，状态码被调用方消费 → 📌 USED
```

## 接收此污点的子函数

| 函数 | 调用位置 | 接收的形参 |
|------|---------|-----------|
| `cdi_parser_validate_vendor_name()` | L197 | `vendor` → 形参 `name` |
| `cdi_parser_validate_class_name()` | L207 | `class` → 形参 `name` |

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `name[0]` | `isalpha()` | L175 | 首字符分类标准库函数 → 🟡 EXPORT |
| `name[i]` (循环) | `isalnum()` | L181 | 逐字符分类标准库函数 → 🟡 EXPORT |
| `name[i-1]` | `isalnum()` | L186 | 末字符分类标准库函数 → 🟡 EXPORT |
| `name` | `ERROR()` 日志 | L176/L182/L187 | 脏字符串写入日志输出 → 🟡 EXPORT |
| `name` | `return` 验证结果 | L178/L189 | 状态码被调用方消费 → 📌 USED |

## 关键发现

1. **无新污点载体** — 函数仅读取 `name`，不向任何输出对象写入脏数据
2. **无 DIRECT_SINK** — 本函数体内无 `memcpy`/`strcpy` 带污点大小/指针、无污点数组写、无整数截断
3. **所有 `name[i]` 读取后均传入标准库分类函数** — `isalpha()`/`isalnum()` 为只读语义，不产生新的污点载体
4. **`ERROR()` 调用均为日志函数** — `name` 作为 `%s` 格式化参数写入日志（信息泄露风险，但非内存安全漏洞）
5. **验证结果（return 0/-1）被调用方消费** — 状态码本身干净，但调用方根据此结果决定是否拒绝脏输入