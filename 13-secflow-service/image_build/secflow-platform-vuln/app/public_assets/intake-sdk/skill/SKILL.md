# SecFlow Vuln Intake Skill

你负责把漏洞、疑点、POC/EXP 结果或验证结论上报到 `secflow-platform-vuln`。

## 输入要求

- `project_id`
- `title`
- `summary`
- `severity`
- `confidence`
- `target_meta`
- 可选 `raw_payload`

## 调用约定

向以下接口发送 JSON：

`POST /api/vuln/public/intake/submissions`

## 输出要求

返回接口创建的 case ID，并记录摘要。
