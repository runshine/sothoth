# 数据流追踪: cdi_container_edits_apply

## 函数信息
- 文件: src/daemon/modules/device/cdi/behavior/cdi_container_edits.c
- 行号: L431-L455
- 签名: `int cdi_container_edits_apply(cdi_container_edits *e, oci_runtime_spec *spec)`

## 污点源
| 输入参数 | 类型 | 污点来源 |
|---------|------|----------|
| `e` | cdi_container_edits * | 🔴 TAINTED — 外部 CDI 配置文件解析后的容器编辑对象载体，其中 `env[]`、`device_nodes[]`、`mounts[]`、`hooks[]` 等字段由外部输入的 CDI Spec JSON 数据填充 |

## 新导入的污点对象
- 无 — 本函数不通过 Recv/Read/Decode 等调用从外部导入新的污点数据

## 传播路径

### INPUT-1: e (cdi_container_edits *) 🔴 TAINTED
```
├── [L432] spec == NULL → 条件判断，非传播
├── [L436] e == NULL → 条件判断，非传播
├── [L439] e->env_len → env_len 🔴 TAINTED (字段提取)
│   └── [L439] if (e->env_len > 0) → 条件判断，非传播
│       └── [L440] spec_add_multiple_process_env(spec, (const char **)e->env, e->env_len)
│           ⚠️ DIRECT_SINK: e->env[] 环境变量内容直接写入 spec->process->env
│           → 📎 spec_add_multiple_process_env
│       └── [L442] if (ret != 0) → 错误处理，非传播
├── [L443] apply_cdi_device_nodes(e, spec)
│   ⚠️ DIRECT_SINK: e 中设备节点数据写入 spec->linux->devices
│   → 📎 apply_cdi_device_nodes
│       └── [L445] if (ret != 0) → 错误处理，非传播
├── [L447] apply_cdi_mounts(e, spec)
│   ⚠️ DIRECT_SINK: e 中挂载信息写入 spec->mounts
│   → 📎 apply_cdi_mounts
│       └── [L449] if (ret != 0) → 错误处理，非传播
└── [L451] apply_cdi_hooks(e, spec)
    ⚠️ DIRECT_SINK: e 中钩子配置写入 spec->hooks
    → 📎 apply_cdi_hooks
    └── [L453] if (ret != 0) → 错误处理，非传播
```

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| `e->env[], e->env_len` | `spec_add_multiple_process_env` | L440 | 环境变量写入 OCI Spec process.env |
| `e->device_nodes[]` | `apply_cdi_device_nodes` | L443 | 设备节点写入 OCI Spec linux.devices |
| `e->mounts[]` | `apply_cdi_mounts` | L447 | 挂载信息写入 OCI Spec mounts |
| `e->hooks[]` | `apply_cdi_hooks` | L451 | 钩子配置写入 OCI Spec hooks |

## 跟入表格
| 子函数 | 调用行 | 接收的形参 | 说明 |
|--------|--------|-----------|------|
| `spec_add_multiple_process_env` | L440 | `e->env, e->env_len` | 环境变量写入 OCI Spec process.env |
| `apply_cdi_device_nodes` | L443 | `e, spec` | 设备节点写入 OCI Spec linux.devices |
| `apply_cdi_mounts` | L447 | `e, spec` | 挂载信息写入 OCI Spec mounts |
| `apply_cdi_hooks` | L451 | `e, spec` | 钩子配置写入 OCI Spec hooks |

---

*本报告仅追踪数据流，不做漏洞评估。*