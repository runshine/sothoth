# SecFlow Vuln Plugin SDK

适合扫描器插件、规则引擎、分析微服务直接把结果认证上报到漏洞生命周期引擎。

## 集成建议

- 在插件完成一次疑点识别后调用认证上报接口（Bearer Token）
- 将插件自身标识写入 `reporter.name`、`reporter.version`、`reporter.type`
- 将目标对象统一写入 `subject`
- 将原始扫描结果、运行上下文、自定义字段放进 `metadata`
- 将文件、目录树、报告、截图等原始产物放进 `artifacts`

## 文件说明

- `plugin_example.py`: Python 插件接入样例
- `example-payload.json`: 结构化示例
