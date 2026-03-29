# SecFlow Vuln CLI SDK

使用 `curl` 或 Python 脚本向 `secflow-platform-vuln` 匿名上报漏洞。

## 快速开始

1. 准备 `project_id`
2. 编辑 `payload.json`
3. 执行：

```bash
curl -X POST "${SECFLOW_VULN_BASE:-http://localhost:8080}/api/vuln/public/intake/submissions" \
  -H 'Content-Type: application/json' \
  --data @payload.json
```

## 文件说明

- `report_vuln.py`: Python 命令行示例
- `example-command.json`: 示例命令与 payload
- `payload-template.json`: 最小匿名上报报文
