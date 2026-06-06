# 数据流追踪: parse_args

## 函数信息
- 文件: src/cmd/isulad/isulad_commands.c
- 行号: L224-L251
- 签名: `int parse_args(struct service_arguments *args, int argc, const char **argv)`

## 污点源识别

| 编号 | 变量 | 类型 | 污点状态 | 说明 |
|------|------|------|----------|------|
| INPUT-1 | argc | int | 🔴 TAINTED | 外部命令行输入，由 main() 传入 |

## 数据流树状图

### INPUT-1: argc (int) 🔴 TAINTED — 外部命令行输入
├── [L233] command_init_isulad(&cmd, ..., argc, ...) → 📎 command_init_isulad
│   └── [L214] self->argc = argc - 1 → self->argc 🔴 TAINTED (内部传播,仅用于 command_t 结构体)
└── [L234] command_parse_args(&cmd, &args->argc, &args->argv)
    └── ⚠️ **NEW CARRIER**: args->argc 🔴 TAINTED (由 command_parse_args 输出参数写入)
    └── ⚠️ **NEW CARRIER**: args->argv 🔴 TAINTED (由 command_parse_args 输出参数写入)
        ├── [L239] if (args->argc > 0) → 🟢 CLEANED (循环/条件守卫,无内存操作)
        └── [L243] args->argv[0] → 📌 USED (printf 输出未解析参数)

## 逐行追踪详情

| 行号 | 代码片段 | 分析结果 |
|------|----------|----------|
| L224 | `int parse_args(struct service_arguments *args, int argc, const char **argv)` | `argc` 作为函数形参接收外部脏数据 → 🔴 TAINTED |
| L233 | `command_init_isulad(&cmd, options, ..., argc, (const char **)argv, ...)` | `argc` 作为实参传入 `command_init_isulad` → 📎 见跟入列表 |
| L234 | `command_parse_args(&cmd, &args->argc, &args->argv)` | `&args->argc`、`&args->argv` 作为输出参数传入；`command_parse_args` 将解析后的脏数据写入这些输出参数 → 产生 **NEW CARRIER** |
| L239 | `if (args->argc > 0)` | 使用 NEW CARRIER `args->argc` 做条件比较；无内存操作 → 🟢 CLEANED |
| L243 | `printf("unresolved arguments: %s;", args->argv[0])` | 使用 NEW CARRIER `args->argv[0]` 做 printf 输出 → 📌 USED |

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| args->argc (NEW CARRIER) | USED | L239 | 用于 if 条件判断,作为解析后剩余参数计数 |
| args->argv[0] (NEW CARRIER) | USED | L243 | printf 输出未解析的命令行参数 |

## 高危模式 (DIRECT_SINK)

> 本函数中 `argc` 的高危使用：**无直接高危 sink**。`argc` 仅作为参数传递到 `command_init_isulad`，以及由 `command_parse_args` 写入到输出参数后用于条件/输出消费。