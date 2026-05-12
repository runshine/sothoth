# SecFlow Binary Evolution Center

`secflow-app-binary-evolution-center` 用于围绕已人工收敛的数据流漏洞案例，批量创建多轮 evolution replay，并沉淀 agent 目录产物。

当前实现包含：

- REST + worker 一体代码结构
- 任务预览、创建、列表、详情、轮次查询、应用产物、删除
- 与 `secflow-app-dataflow-vuln-scanner` 的 replay-ready / create-evolution 联动
- 进化目录初始化、轮次结果统计、规则评分、产物快照与覆盖应用

REST API 前缀：

- `/api/app/binary-evolution`

关键目录：

- 任务目录：`/data/files/<project_id>/app/secflow-app-binary-evolution-center/tasks/<task_id>`
- evolution agent 目录：`/data/files/<project_id>/app/DATAFLOW_VULN_SCANNER/agent-state/evolution/<task_id>/<agent_id>/<nonce>`
- 正常目录备份：`/data/files/<project_id>/app/DATAFLOW_VULN_SCANNER/agent-state/backups/<timestamp>-<task_id>`
