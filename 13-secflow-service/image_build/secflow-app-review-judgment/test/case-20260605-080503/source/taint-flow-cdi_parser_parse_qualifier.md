# 污点流: cdi_parser_parse_qualifier

## 状态: ❌ 函数未找到

### 分析结果
- **目标文件**: src/utils/cutils/utils_file.c
- **目标函数**: cdi_parser_parse_qualifier
- **状态**: 函数在此文件中不存在

### 调用上下文问题
调用者 `util_mkdir_p` (L255-L258) 的实际实现：
```c
int util_mkdir_p(const char *dir, mode_t mode)
{
    return util_mkdir_p_userns_remap(dir, mode, NULL);
}
```

该函数只调用 `util_mkdir_p_userns_remap`，未调用 `cdi_parser_parse_qualifier`。

### 结论
污点传播终止 — 目标函数不存在于指定源文件。