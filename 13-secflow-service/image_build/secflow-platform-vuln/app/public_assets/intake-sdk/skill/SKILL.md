# SecFlow Vuln Intake Skill

你负责把漏洞线索、疑点、POC/EXP 结果或验证结论上报到 `secflow-platform-vuln`。

## 输入要求

- `project_id`
- `reporter`
- `title`
- `summary`
- `severity`
- `confidence`
- `subject`
- 可选 `evidence`
- 可选 `artifacts`
- 可选 `metadata`

## 调用约定

向以下接口发送 JSON：

`POST /api/vuln/public/intake/submissions`

## 输出要求

返回接口创建的疑点 ID，并记录摘要。
