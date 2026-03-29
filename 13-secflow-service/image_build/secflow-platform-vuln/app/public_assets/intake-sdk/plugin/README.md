# SecFlow Vuln Plugin SDK

适合扫描器插件、规则引擎、分析微服务直接把结果匿名上报到漏洞生命周期引擎。

## 集成建议

- 在插件完成一次漏洞识别后调用匿名上报接口
- 将原始扫描结果放进 `raw_payload`
- 将插件自身标识写入 `reporter_name` 和 `source_meta`

## 文件说明

- `plugin_example.py`: Python 插件接入样例
- `example-payload.json`: 结构化示例
