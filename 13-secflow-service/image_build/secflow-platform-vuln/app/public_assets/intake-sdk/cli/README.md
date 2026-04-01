# SecFlow Vuln CLI SDK

使用 `curl` 或 Python 脚本向 `secflow-platform-vuln` 进行认证漏洞上报。

## 快速开始

1. 准备 `project_id`
2. 准备有效的 Bearer Token（auth 微服务登录态）
3. 编辑 `payload.json`
4. 执行：

```bash
curl -X POST "${SECFLOW_VULN_BASE:-http://localhost:8080}/api/vuln/public/intake/submissions" \
  -H "Authorization: Bearer ${SECFLOW_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data @payload.json
```

## 文件说明

- `report_vuln.py`: Python 命令行示例
- `example-command.json`: 示例命令与 payload
- `payload-template.json`: 最小认证上报报文
