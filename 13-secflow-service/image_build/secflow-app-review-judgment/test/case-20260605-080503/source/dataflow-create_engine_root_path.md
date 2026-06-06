# 数据流漏洞追踪: create_engine_root_path

## 函数信息
- 文件: src/daemon/modules/runtime/engines/engine.c
- 行号: L116-L176
- 签名: `static int create_engine_root_path(const char *path)`

## 父上下文
- 调用者: rt_lcr_exec (src/daemon/modules/runtime/engines/lcr/lcr_rt_ops.c)
- 调用位置: L216
- 传入污点: `params->rootpath`

## 数据流树状图

### INPUT-1: path (const char*) 🔴 TAINTED
├── [L130] if (util_dir_exists(path)) → 目录存在检查
│   └── 存在则返回0，不执行后续创建
├── [L141] util_mkdir_p(path, mode) → 📎 见跟入列表
│   └── ⚠️ 高危: 污点路径控制目录创建位置
├── [L148] set_file_owner_for_userns_remap(path, userns_remap) → 📎 见跟入列表
│   └── ⚠️ 高危: 污点路径控制文件所有者设置
├── [L154] tmp_path = util_strdup_s(path) → tmp_path 🔴 TAINTED
│   ├── [L155] p = strrchr(tmp_path, '/') → 查找最后一个'/'字符
│   ├── [L160] *p = '\0' → 截断获取父目录
│   └── [L162] set_file_owner_for_userns_remap(tmp_path, userns_remap) → 📎 见跟入列表
│       └── ⚠️ 高危: 污点路径的父目录所有者设置
└── [L175] return ret (0成功/-1失败)

## 关键高危模式
⚠️ **DIRECT_SINK**: `util_mkdir_p(path, mode)` — 污点路径控制目录创建位置，可能导致：
- 任意位置创建目录
- 路径穿越攻击

⚠️ **DIRECT_SINK**: `set_file_owner_for_userns_remap(path, userns_remap)` — 污点路径控制文件所有者设置

⚠️ **DIRECT_SINK**: `set_file_owner_for_userns_remap(tmp_path, userns_remap)` — 从污点路径提取的父目录所有者设置

⚠️ **字符串解析风险**: `strrchr(tmp_path, '/')` 和 `*p = '\0'` 截断父目录
- 未验证路径格式（多个'/'、以'/'开头等）
- 截断后可能产生意外父目录

## 污点终点汇总
| 脏数据 | 终点 | 位置 | 说明 |
|--------|------|------|------|
| path | util_mkdir_p | L141 | 创建目录操作 |
| path | set_file_owner_for_userns_remap | L148 | 设置文件所有者 |
| tmp_path (from path) | set_file_owner_for_userns_remap | L162 | 设置父目录所有者 |

## 漏洞候选识别
1. **路径穿越漏洞候选**: `path` 控制目录创建位置，`util_mkdir_p` 使用 `path` 直接创建目录而无路径验证
2. **父目录解析错误**: `strrchr` 查找最后一个'/'的位置，特殊路径格式可能导致意外行为
3. **所有权设置攻击面**: 污点路径传入 `set_file_owner_for_userns_remap` 可能用于修改任意文件所有权（当启用USERNS_REMAP时）