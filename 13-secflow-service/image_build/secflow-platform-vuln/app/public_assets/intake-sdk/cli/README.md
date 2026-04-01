# SecFlow Vuln CLI SDK

使用 `curl` 或 Python 脚本向 `secflow-platform-vuln` 进行认证漏洞上报。

## 认证要求

1. 准备 `project_id`
2. 准备有效的 Bearer Token（auth 微服务登录态）
3. 选择上报模式并编辑对应 payload
4. 执行上报请求

匿名上报不再支持。

## 流程一：简易上报（不带文件）

适用场景：快速创建疑点，仅包含标题、目标、证据摘要。

```bash
curl -X POST "${SECFLOW_VULN_BASE:-http://localhost:8080}/api/vuln/public/intake/submissions" \
  -H "Authorization: Bearer ${SECFLOW_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data @payload-simple.json
```

## 流程二：正常上报（带文件/目录结构）

适用场景：需要一起上报扫描结果、日志、目录树或外部文件引用。

```bash
curl -X POST "${SECFLOW_VULN_BASE:-http://localhost:8080}/api/vuln/public/intake/submissions" \
  -H "Authorization: Bearer ${SECFLOW_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data @payload-with-files.json
```

目录结构通过 `artifacts[].children` 递归描述；大文件建议使用 `content_ref` 引用。

## 通用命令模板

```bash
curl -X POST "${SECFLOW_VULN_BASE:-http://localhost:8080}/api/vuln/public/intake/submissions" \
  -H "Authorization: Bearer ${SECFLOW_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data @payload.json
```

## 文件说明

- `report_vuln.py`: Python 命令行示例
- `example-command.json`: 双模式命令示例（简易/带文件）
- `payload-simple.json`: 简易上报（不带文件）示例
- `payload-with-files.json`: 正常上报（带文件/目录）示例
- `payload-template.json`: 通用模板（默认带文件）
