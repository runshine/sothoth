# 污点流: name

## 污点源
- name 🔴 TAINTED

## 新导入的污点对象
- syslog_tag 🔴 TAINTED — 由 `isula_sub_string(name, 0, SHORT_ID_LEN)` 在 L416 返回后赋值

## 传播路径
```
### INPUT: name (const char*) 🔴 TAINTED
├── [L416] syslog_tag = isula_sub_string(name, 0, SHORT_ID_LEN)
│   └── syslog_tag 🔴 TAINTED (从 name 提取的前15字符)
│       └── [L427] openlog(syslog_tag, LOG_PID, facility_num) 📌 USED
└── [L420] ERROR("Empty syslog tag for :%s", name) — 仅用于日志记录，非安全敏感
```

## 接收此污点的子函数
| 函数 | 调用位置 | 接收的形参 |
|------|---------|----------|
| isula_sub_string | L416 | name |
| openlog | L427 | syslog_tag |