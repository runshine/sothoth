# 漏洞扫描 Dashboard

用于实时查看 `runs/` 下所有漏洞扫描运行记录、中间产物和评审结果，避免运行时手动打开文件。

## 启动

```bash
python3 run_dashboard.py --port 8501
# 或
python3 dashboard/server.py --runs-dir runs --port 8501
```

打开：<http://localhost:8501>

## 功能

- Runs 列表：状态、模型、轮次、结果通过/失败数。
- 概览页：分数趋势、当前 issues、结果生命周期 manifest、评审轮次时间线。
- 评审轮次：global review / result review 详情，展示 parser/schema repair、failure scope、plateau/removed/unreviewed 指标，支持直接打开 canonical JSON。
- 漏洞结果：查看每个 `result_*.md`、生命周期角色、补充/撤回状态、已迁移 `removed_results/` 和对应评审 JSON。
- 会话记录：查看 worker / reviewer 每次调用的 Prompt、System Prompt、Response、stdout/stderr/stdout_events。
- 文件浏览：聚合展示 config、input、summary、previous_limitations、supporting_docs、removed_results、manifest、checkpoints、review、results、sessions 等中间文件。
- 实时刷新：默认每 6 秒自动刷新当前 run 和 runs 列表。

## API

- `GET /api/runs`
- `GET /api/runs/{name}`
- `GET /api/runs/{name}/cycles/{cycle}`
- `GET /api/runs/{name}/sessions`
- `GET /api/runs/{name}/files`
- `GET /api/runs/{name}/file?path=...`
- `GET /api/runs/{name}/log?lines=500`
