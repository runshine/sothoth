# 污点流: `说明:` (device)

## 污点源
- `device` (const char*) 🔴 TAINTED — 调用者传入的外部设备名称字符串，可能来自 CDI 配置或容器设备规格

## 新导入的污点对象
- `*name` 🔴 TAINTED — 由 L129 `*name = parts[1]` 写入，承载了污点设备名中被 `=` 分隔的后半部分
- `*vendor` 🔴 TAINTED — 由 `cdi_parser_parse_qualifier` 在 L163 内部 `*vendor = parts[0]` 写入，承载了污点 qualifier 中 `/` 前半部分
- `*class` 🔴 TAINTED — 由 `cdi_parser_parse_qualifier` 在 L164 内部 `*class = parts[1]` 写入，承载了污点 qualifier 中 `/` 后半部分

## 传播路径
```
### INPUT-1: device (const char*) 🔴 TAINTED
├── [L122] if (device == NULL || device[0] == '/') → 仅作校验，无污点传播
├── [L125] parts = util_string_split_n(device, '=', 2)
│           └─ util_string_split_n 是内部工具函数，device 作为输入参与分词
│           └─ parts[0], parts[1] 现在持有污点数据
├── [L126] 校验 parts 结构有效性 → 仅条件判断，无新污点
├── [L129] *name = parts[1] 
│           └─ **OUTPUT PARAMETER** *name 接收污点内容 → 🔴 TAINTED 新载体
│           └─ parts[1] 被置 NULL
└── [L131] cdi_parser_parse_qualifier(parts[0], vendor, class)
            └─ parts[0] (污点数据) 作为第1实参传入 → 📎 见跟入列表
            └─ vendor, class 输出指针由子函数填充

### 新污点载体: *name 🔴 TAINTED
└── [L129] 由 device 分隔得到，写入 *name 输出参数
    └── 后续由调用者消费/使用

### 新污点载体: *vendor 🔴 TAINTED
└── 由 cdi_parser_parse_qualifier 内部 [L163] *vendor = parts[0] 写入
    └── parts[0] 源自 device 中 `=` 前部分再经 `/` 分割

### 新污点载体: *class 🔴 TAINTED
└── 由 cdi_parser_parse_qualifier 内部 [L164] *class = parts[1] 写入
    └── parts[1] 源自 device 中 `=` 前部分经 `/` 分割
```

## 接收此污点的子函数

| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| `cdi_parser_parse_qualifier` | L131 | `parts[0]` (第1形参 kind) |

## DIRECT_SINK 检查

**无 DIRECT_SINK 风险在本函数内:**
- `util_string_split_n(device, '=', 2)` — 分隔大小固定为 2，非污点控制
- `parts[0]` / `parts[1]` 访问 — 索引固定，无越界风险
- `*name = parts[1]` — 普通指针赋值，非内存操作危险

---

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `device` | `*name` | L129 | device 经 `=` 分割后半部分写入 name 输出参数 |
| `device`→`parts[0]` | `*vendor` | cdi_parser_parse_qualifier L163 | device 经 `=` 和 `/` 双重分割后写入 vendor |
| `device`→`parts[0]` | `*class` | cdi_parser_parse_qualifier L164 | device 经 `=` 和 `/` 双重分割后写入 class |