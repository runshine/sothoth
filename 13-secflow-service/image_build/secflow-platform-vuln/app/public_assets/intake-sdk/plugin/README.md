# SecFlow Vuln Plugin SDK

适合扫描器插件、规则引擎、分析微服务直接把结果认证上报到漏洞生命周期引擎。
仅支持认证上报，不支持匿名上报。

## 集成建议

- 在插件完成一次疑点识别后调用认证上报接口（Bearer Token）
- 将插件自身标识写入 `reporter.name`、`reporter.version`、`reporter.type`
- 将目标对象统一写入 `subject`
- 将原始扫描结果、运行上下文、自定义字段放进 `metadata`
- 将文件、目录树、报告、截图等原始产物放进 `artifacts`

## 两种推荐流程

1. 简易上报（不带文件）：提交结构化字段和 `evidence` 即可。
2. 正常上报（带文件）：在 `artifacts` 中附带文件、目录树或 `content_ref` 引用。

## 文件说明

- `plugin_example.py`: Python 插件接入样例
- `example-payload.json`: 双模式结构化示例（简易/带文件）
