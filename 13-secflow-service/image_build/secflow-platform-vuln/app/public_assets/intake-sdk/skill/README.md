# SecFlow Vuln Skill Package

本包用于 AI Agent / Skill 方式接入认证漏洞上报。
仅支持 Bearer Token 认证上报，不支持匿名。

包含：

- `SKILL.md`
- `example-skill-call.json`
- `openapi-reference.json`

使用时让 Agent 读取 `SKILL.md`，并将实际漏洞内容替换进示例请求。
`example-skill-call.json` 提供两种模式：简易上报（不带文件）和正常上报（带文件/目录）。
