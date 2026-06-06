# 污点流: `args` (struct service_arguments *)

## 污点源
- `args` 🔴 TAINTED — 外部输入，承载命令行参数 `argv` 和 JSON 配置内容

## 新导入的污点对象
- `g_isulad_conf.server_conf` 🔴 TAINTED — 由 L1574 赋值语句写入，外部输入的指针被存入全局变量

## 传播路径
```
### INPUT: args (struct service_arguments *) 🔴 TAINTED
├── [L1560] ret = pthread_rwlock_init(&g_isulad_conf.isulad_conf_rwlock, NULL);
│           └── ret = 0 → ret 🟢 CLEANED (状态码)
├── [L1562] if (ret != 0) { ERROR; ret = -1; goto out; }
├── [L1565] if (pthread_rwlock_wrlock(&g_isulad_conf.isulad_conf_rwlock) != 0) {
│           ERROR; ret = -1; goto out;
│         }
├── [L1570] if (g_isulad_conf.server_conf != NULL) {
│           service_arguments_free(g_isulad_conf.server_conf);
│           free(g_isulad_conf.server_conf);
│         }
└── [L1574] g_isulad_conf.server_conf = args;
            └─→ g_isulad_conf.server_conf 🔴 TAINTED ⚠️ 新污点载体 (全局变量)
    [L1576] if (pthread_rwlock_unlock(...) != 0) { ERROR; ret = -1; goto out; }
    [L1582] out: return ret;
            └── ret 🟢 CLEANED (返回状态码)
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| (无) | — | 函数内部未将 `args` 传递给任何子函数 |