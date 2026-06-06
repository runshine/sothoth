# 数据流追踪: validate_vendor_or_class_name

## 函数信息
- 文件: src/daemon/modules/device/cdi/behavior/parser/cdi_parser.c
- 行号: L169-L191
- 签名: `static int validate_vendor_or_class_name(const char *name)`

## 分析目标
- 参数: `name` (const char*) - 🔴 TAINTED
- 说明: 外部输入的厂商名或类别名，来自网络/配置

## 数据流树状图

### INPUT: name (const char*) 🔴 TAINTED
├── [L172] if (name == NULL) → 空指针检查
├── [L179] ERROR("%s, should start with letter", name) → 📌 USED (错误日志)
│   └── 读取 name[0] 进行 isalpha 检查
├── [L180-182] 循环: for (i=1; name[i]!='\0'; i++)
│   ├── [L181] isalnum(name[i]) || name[i]=='_' || name[i]=='-' || name[i]=='.' → 验证字符合法性
│   └── [L182] ERROR("Invalid character '%c' in name %s", name[i], name) → 📌 USED (错误日志)
└── [L188] ERROR("%s, should end with a letter or digit", name) → 📌 USED (错误日志)

## 污点传播说明
- `name` 仅为读取使用，未被写入或拷贝到任何载体对象
- 循环索引 `i` 通过遍历 null 终止字符串推导，非外部污点来源
- 无污点数据写入输出参数的情况
- 无新污点载体被创建

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| name | 📌 USED | L179 | 通过 ERROR 宏输出到日志，仅作为消息内容 |
| name | 📌 USED | L182 | 通过 ERROR 宏输出到日志 |
| name | 📌 USED | L188 | 通过 ERROR 宏输出到日志 |

## 调用的子函数（接收污点数据）
| 序号 | 函数 | 位置 | 接收的参数 | 说明 |
|------|------|------|------------|------|
| 1 | isalpha | L179 | name[0] | 标准C库函数，验证首字符 |
| 2 | isalnum | L181 | name[i] | 标准C库函数，验证后续字符 |
| 3 | ERROR | L179,L182,L188 | name | 日志宏，仅用于输出显示 |

## 安全评估
- ⚠️ DIRECT_SINK: **无** - 该函数仅为校验函数，仅读取数据不做危险操作
- 未发现缓冲区溢出、格式化字符串、指针运算等危险操作