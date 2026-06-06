# 污点流: validate_vendor_or_class_name(name)

## 函数信息
- **文件:** `src/daemon/modules/device/cdi/behavior/parser/cdi_parser.c`
- **行号:** L169–L195
- **签名:** `static int validate_vendor_or_class_name(const char *name)`

## 污点源
- `name` (const char*) 🔴 TAINTED — 外部 CDI 配置文件输入的 vendor/class 名称，在通过验证之前视为脏数据

## 新导入的污点对象
**无** — 本函数内无任何输出参数、缓冲区或消息对象接收脏数据写入

## 传播路径

```
### INPUT-1: name (const char*) 🔴 TAINTED — 外部 CDI 配置输入
├── [L171] if (name == NULL) → 空指针检查，name 仅作为指针值读取
├── [L174] isalpha(name[0]) → name[0] 读取后传入 → 🟡 EXPORT stdlib (isalpha)
│   └── [L174] ERROR("...%s...", name) → name 传入日志函数 → 🟡 EXPORT logging
│       └── [L175] return -1 → 错误码返回，干净数据
└── [L176] for (i=1; name[i]!='\0'; i++) → 循环遍历脏字符数组
    ├── [L177] isalnum(name[i]) || name[i]=='_'|'-'|'.' → name[i] 读取后传入 → 🟡 EXPORT stdlib (isalnum)
    │   ├── [L177] ERROR("Invalid char '%c' in name %s", name[i], name) → name[i] + name 传入日志 → 🟡 EXPORT logging
    │   │   └── [L178] return -1 → 错误码返回，干净数据
    │   └── [L179] continue → 继续循环
    └── [L180] if (!isalnum(name[i-1])) → name[i-1] 读取后传入 → 🟡 EXPORT stdlib (isalnum)
        ├── [L180] ERROR("...should end with letter or digit", name) → name 传入日志 → 🟡 EXPORT logging
        │   └── [L181] return -1 → 错误码返回，干净数据
        └── [L182] return 0 → 验证通过，状态码被调用方消费 → 📌 USED
```

## 接收此污点的子函数

| 函数 | 调用位置 | 接收的形参 | 备注 |
|------|---------|-----------|------|
| `cdi_parser_validate_vendor_name()` | L197 (cdi_parser.c) | `vendor` → `name` | 同一文件中定义，vendor 继承上级污点 |
| `cdi_parser_validate_class_name()` | L207 (cdi_parser.c) | `class` → `name` | 同一文件中定义，class 继承上级污点 |

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `name[0]` | `isalpha()` | L174 | 字符分类标准库函数 → 🟡 EXPORT |
| `name[i]` (循环) | `isalnum()` | L177 | 逐字符分类标准库函数 → 🟡 EXPORT |
| `name[i-1]` | `isalnum()` | L180 | 末字符分类标准库函数 → 🟡 EXPORT |
| `name` | `ERROR()` 日志 | L174/L177/L180 | 脏字符串写入日志输出 → 🟡 EXPORT |
| `name` | `return` 验证结果 | L182/L185/L188 | 状态码被调用方消费 → 📌 USED |

## 关键发现

1. **无新污点载体** — 函数仅读取 `name`，不向任何输出对象写入脏数据
2. **直接接收子函数** — 无 (`validate_vendor_or_class_name` 自身无子函数调用)
3. **DIRECT_SINK 风险** — **无** — 本函数体内无 `memcpy`/`strcpy` 带污点大小/指针、无污点数组写、无整数截断
4. **`name` 仅被读取** — 所有 `name[i]` 读取后直接传入 `isalpha()`/`isalnum()` 标准库分类函数，不产生新的污点载体