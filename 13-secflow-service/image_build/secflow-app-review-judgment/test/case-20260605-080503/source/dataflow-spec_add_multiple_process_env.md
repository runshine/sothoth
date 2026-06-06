# 数据流追踪: spec_add_multiple_process_env

## 函数信息
- 文件: src/daemon/modules/spec/specs.c
- 签名: `int spec_add_multiple_process_env(oci_spec_t *oci_spec, const char **envs, size_t env_len)`

## 污点源
| ID | 变量 | 类型 | 说明 |
|----|------|------|------|
| INPUT-0 | `oci_spec` | `oci_spec_t *` | 🔴 TAINTED — 调用者控制的容器规格指针 |
| INPUT-1 | `envs` | `const char **` | 🔴 TAINTED — 外部环境变量字符串数组，由调用者从 CDI 配置/容器规格传入 |
| INPUT-2 | `env_len` | `size_t` | 🔴 TAINTED — 外部传入的环境变量数组长度 |

## 新导入的污点对象
（当前函数自身未产生新的污点载体；污点传播至子函数后由子函数内部产生新载体）

## 传播路径（仅限当前函数范围）

### INPUT-0: oci_spec (oci_spec_t *) 🔴 TAINTED
```
└── [L2688] make_sure_oci_spec_process(oci_spec) → 📎 make_sure_oci_spec_process (接收污点指针)
    └── [L2694] defs_process_add_multiple_env(oci_spec->process, envs, env_len) → 📎 defs_process_add_multiple_env
        └── (oci_spec->process 暴露至子函数)
```

### INPUT-1: envs (const char **) 🔴 TAINTED
```
├── [L2679] if (envs == NULL || env_len == 0) → 仅作 NULL 校验，无风险
└── [L2694] defs_process_add_multiple_env(oci_spec->process, envs, env_len)
    └── 📎 污点指针数组作为实参传入子函数
```

### INPUT-2: env_len (size_t) 🔴 TAINTED
```
├── [L2681] if (envs == NULL || env_len == 0) → 仅作零值检查，无风险
└── [L2694] defs_process_add_multiple_env(..., envs, env_len)
    └── 📎 污点长度作为实参传入子函数（控制子函数内循环上界）
```

## 高危模式汇总（当前函数范围）
| 模式 | 位置 | 说明 |
|------|------|------|
| 无 DIRECT_SINK | — | 当前函数自身无 memcpy/strcpy/类型截断等危险操作 |

> ⚠️ **注意**：危险操作（污点边界控制循环、污点索引写入、realloc 大小控制）存在于**子函数** `defs_process_add_multiple_env` 内部。Worker 无需跟入子函数内部实现，只需正确记录调用关系。

## 污点终点汇总（当前函数范围）
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `oci_spec` | `make_sure_oci_spec_process()` | L2688 | 污点指针暴露给外部 |
| `oci_spec->process` | `defs_process_add_multiple_env()` | L2694 | 污点结构体成员作为实参 |
| `envs` | `defs_process_add_multiple_env()` | L2694 | 污点指针数组作为实参 |
| `env_len` | `defs_process_add_multiple_env()` | L2694 | 污点长度控制子函数内循环 |

---

*本报告仅追踪数据流，不做漏洞评估。*