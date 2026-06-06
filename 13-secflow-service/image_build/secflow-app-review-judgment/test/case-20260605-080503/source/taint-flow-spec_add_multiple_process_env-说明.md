# 数据流追踪: spec_add_multiple_process_env — 参数 `说明:`

## 函数信息
- **文件**: src/daemon/modules/spec/specs.c
- **行号**: L2675-L2697
- **签名**: `int spec_add_multiple_process_env(oci_runtime_spec *oci_spec, const char **envs, size_t env_len)`

## 污点源

### INPUT-1: envs (const char **) 🔴 TAINTED
- **来源**: 外部调用者从 CDI 配置/容器规格传入的环境变量字符串数组
- **语义**: 原始污点数据（容器运行时外部输入），每个 `envs[i]` 承载 KEY=VALUE 格式字符串

### INPUT-2: env_len (size_t) 🔴 TAINTED
- **来源**: 外部调用者传入的环境变量数组元素计数
- **语义**: 控制后续污点传播范围和循环次数

## 新导入的污点对象

| 名称 | 行号 | 来源 | 类型 |
|------|------|------|------|
| `dp->env[i]` | L2634 | `add_env()` 内部 `dp->env[i] = util_strdup_s(env)` 写入结构体数组 | struct-member-write |
| `dp->env[dp->env_len]` | L2643 | `add_env()` 内部 `dp->env[dp->env_len] = util_strdup_s(env)` 写入结构体数组 | struct-member-write |
| `oci_spec->process->env[]` | L2643 调用后 | `defs_process_add_multiple_env` 遍历 envs 并逐个写入 `dp->env[]` | output-struct-member |

## 传播路径

```
### INPUT-1: envs (const char **) 🔴 TAINTED
├── [L2679] if (envs == NULL || env_len == 0) → 仅 NULL 校验，无新污点
└── [L2696] defs_process_add_multiple_env(oci_spec->process, envs, env_len)
    └── [L2657] for (i = 0; i < env_len; i++) → 污点循环边界 env_len 控制次数
        ├── [L2659] util_valid_split_env(envs[i], &key, NULL) → 解析污点字符串
        │   └── util_valid_split_env → 🟡 EXPORT (utils_verify.c:L654)
        └── [L2663] add_env(dp, envs[i], key) → 📎 add_env (static)
            └── [add_env 内部 — specs.c:L2622]
                ├── [L2625] for (i = 0; i < dp->env_len; i++) → 遍历已有 env
                │   ├── [L2628] util_valid_split_env(dp->env[i], &oci_key, NULL) → 解析已有污点
                │   └── [L2634] dp->env[i] = util_strdup_s(env)
                │       └── ⚠️ DIRECT_SINK: 污点 envs[i] 字符串写入 dp->env[i] 数组
                └── [L2637] util_mem_realloc((void **)&dp->env, (dp->env_len + 1) * sizeof(char *), ...)
                    └── ⚠️ DIRECT_SINK: dp->env_len 控制 realloc 大小，env_len 间接控制增长上限
                    └── [L2643] dp->env[dp->env_len] = util_strdup_s(env)
                        └── ⚠️ DIRECT_SINK: 污点 envs[i] 字符串写入 dp->env[dp->env_len] 数组
                        └── util_strdup_s → 🟡 EXPORT
                    └── [L2644] dp->env_len++

### INPUT-2: env_len (size_t) 🔴 TAINTED
├── [L2681] if (envs == NULL || env_len == 0) → 零值检查（仅作校验）
├── [L2688] make_sure_oci_spec_process(oci_spec) → 未使用 env_len → 🟢 CLEANED (不污染)
└── [L2694/L2696] defs_process_add_multiple_env(oci_spec->process, envs, env_len)
    └── [L2657] for (i = 0; i < env_len; i++) → ⚠️ DIRECT_SINK: 污点边界控制循环次数
        └── ⚠️ DIRECT_SINK: 若 env_len > 实际 envs 分配空间 → 越界读 envs[i]
    └── 📌 USED: env_len 作为循环上界传递给子函数 defs_process_add_multiple_env

### NEW CARRIER: oci_spec->process->env[] 🔴 TAINTED (由 defs_process_add_multiple_env 内部写入)
└── 由 L2643 `dp->env[dp->env_len] = util_strdup_s(env)` 逐个写入污点字符串
    └── oci_spec->process->env (即 dp->env) 🔴 TAINTED
        └── 📌 USED: 作为 oci_spec 结构体成员被容器规格承载
```

## 污点终点汇总

| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| env_len | for 循环边界 | L2657 | ⚠️ DIRECT_SINK: 污点边界控制循环次数，env_len 超分配则越界读 envs[i] |
| env_len | realloc 大小 | L2639 | ⚠️ DIRECT_SINK: env_len 通过 dp->env_len 间接控制 realloc 大小增长 |
| dp->env_len | 数组下标 | L2643 | ⚠️ DIRECT_SINK: dp->env_len（由 env_len 累加）作为数组写入索引 |
| envs[i] | util_strdup_s (搜索) | L2634 | ⚠️ DIRECT_SINK: 污点字符串写入 dp->env[i] 数组 |
| envs[i] | util_strdup_s (追加) | L2643 | ⚠️ DIRECT_SINK: 污点字符串写入 dp->env[dp->env_len] 数组 |
| oci_spec->process->env[] | 结构体成员 | L2643 | 📌 USED: 污点字符串被 oci_spec 承载，后续任何使用此 spec 的代码均受影响 |

## 关键发现

1. **⚠️ DIRECT_SINK — 污点循环边界越界读 (L2657)**: `for (i = 0; i < env_len; i++)` 中 `env_len` 为污点。若调用者传入的 `env_len` 大于实际 `envs` 数组的已分配大小，循环将越界访问 `envs[i]`，读入任意内存内容。
2. **⚠️ DIRECT_SINK — 污点 realloc 大小 (L2639)**: `util_mem_realloc` 的增长量 `(dp->env_len + 1) * sizeof(char *)` 中 `dp->env_len` 来自污点 `env_len` 的累加。若累计值超大，可导致整数溢出或分配失败。
3. **⚠️ DIRECT_SINK — 污点数组下标 (L2643)**: `dp->env[dp->env_len] = util_strdup_s(env)` 中 `dp->env_len` 作为数组写入索引，由污点 `env_len` 累加而来。若 `dp->env_len` 超出 `dp->env` 当前分配容量，写入越界。
4. **新导入污点载体 — oci_spec->process->env[] (L2643 后)**: `defs_process_add_multiple_env` 遍历污点 `envs` 并逐个 `util_strdup_s` 写入 `dp->env[]`。所有污点字符串被永久注入 `oci_spec->process->env`，成为 spec 结构体的一部分，影响后续所有使用该 spec 的代码路径。
5. **搜索路径中的污点字符串 (L2634)**: `add_env` 在搜索重复 KEY 时也会写入 `dp->env[i] = util_strdup_s(env)`，同一污点路径重复执行。

## 跟入表格（子函数）

| 函数 | 调用位置 | 接收的形参 | 说明 |
|------|---------|----------|------|
| `defs_process_add_multiple_env` | L2696 | `oci_spec->process`, `envs`, `env_len` | 非 static，在 specs.c:L2648 定义 |
| `add_env` (static) | L2663 | `env` (即 `envs[i]`) | specs.c:L2622，无法进一步跟入 |
| `util_valid_split_env` | L2659, L2628 | `env` 参数 | 🟡 EXPORT — utils_verify.c:L654 |
| `util_strdup_s` | L2634, L2643 | `env` 参数 | 🟡 EXPORT — 标准安全字符串拷贝封装 |

---

*本报告仅追踪数据流，不做漏洞评估。*