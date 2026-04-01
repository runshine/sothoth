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

请求必须携带 Bearer Token，并按 `project_id` 通过项目级权限校验。
匿名上报不支持。

## 推荐工作模式

1. 简易上报（不带文件）  
只提交疑点核心字段（title/subject/evidence），快速创建疑点。
2. 正常上报（带文件）  
在 `artifacts` 携带文件或目录树（`children` 递归），用于后续研判和验证。

## 输出要求

返回接口创建的疑点 ID，并记录摘要。
