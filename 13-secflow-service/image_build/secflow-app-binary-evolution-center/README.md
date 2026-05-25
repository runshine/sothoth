# SecFlow Binary Evolution Center

当前建议先使用单文件命令行工具 `run_evolution.py` 调试数据流漏洞挖掘自进化流程。它不启动 FastAPI、不依赖本服务数据库，也不需要 worker 调度器；只通过 REST 调用 `secflow-app-dataflow-vuln-scanner` 的 replay 接口，并在项目文件目录中生成候选 agent memory、replay payload 和评估报告。

## CLI 快速开始

进入目录：

```bash
cd /home/icsl/sothoth/13-secflow-service/image_build/secflow-app-binary-evolution-center
```

用漏洞平台里勾选的 result 反查原始 normal 任务，然后进化 `pi-worker` + `pi-advisor` memory：

```bash
python3 run_evolution.py \
  --project-id default \
  --direction "降低命令注入误报，不要牺牲真实高危漏洞" \
  --selected-result case-1 --selected-result case-2 \
  --token "$TOKEN" \
  --max-rounds 3
```

绕过漏洞平台，直接指定 dataflow-vuln-scanner 的原始 normal task 调试：

```bash
python3 run_evolution.py \
  --project-id default \
  --direction "不要上报 web 模块里的路径遍历类结果" \
  --source-task tt-source-1,tt-source-2 \
  --expected-result-count 4 \
  --dry-run
```

只生成本地 payload 和 memory，不访问 replay-ready/get_task 预检：

```bash
python3 run_evolution.py \
  --project-id default \
  --direction "调试候选 memory 注入结构" \
  --source-task tt-source-1 \
  --expected-result-count 0 \
  --dry-run \
  --skip-source-validation
```

把最佳轮次晋级为项目 evolution memory：

```bash
python3 run_evolution.py \
  --project-id default \
  --direction "降低误报率" \
  --source-task tt-source-1 \
  --evolve-agents pi-worker \
  --promote
```

查看或关闭项目 evolution memory 开关：

```bash
python3 run_evolution.py --project-id default --show-memory-mode
python3 run_evolution.py --project-id default --disable-memory-mode
```

## CLI 输出

默认输出目录：

```text
/data/files/<project_id>/app/DATAFLOW_VULN_SCANNER/agent-state/evolution-cli/<experiment_id>/
```

关键文件：

- `sources.json`：本次 replay 的源任务集合。
- `experiment-report.json`：实验总报告、每轮分数、meta evaluator 结论、最佳轮次。
- `rounds/round-<n>/<agent_id>/memory/`：候选 agent memory。
- `rounds/round-<n>/replay-payloads/<source_task_id>.json`：提交给 dataflow-vuln-scanner `create-evolution` 的 payload。
- `rounds/round-<n>/round-report.json`：单轮 replay、规则指标、meta evaluator 报告。

`--promote` 后会写入：

```text
/data/files/<project_id>/app/DATAFLOW_VULN_SCANNER/agent-state/promoted-evolution-cli/<experiment_id>/round-<best>/<agent_id>/memory/
/data/files/<project_id>/app/DATAFLOW_VULN_SCANNER/agent-state/evolution-memory-mode.json
```

## 命令行选项

### 基础输入

| 选项 | 用法 |
| --- | --- |
| `--project-id` | 必填。项目 id。用于定位 `<workspace-root>/<project-id>`，也用于 replay 任务和 memory-mode 文件归属。 |
| `--direction` | 进化方向。普通运行必填，例如“降低 SQL 注入误报率”或“不要上报某模块的低危结果”。该文本会写入候选 memory 和 meta evaluator 报告。`--show-memory-mode`、`--disable-memory-mode` 不需要它。 |
| `--selected-result` | 从漏洞平台勾选的 result/case id。可重复，也可逗号分隔。CLI 会读取 result 的 `source_task` 或 `metadata.source`，反查原始 dataflow normal task。 |
| `--selected-results-file` | result/case id 文件。普通文本每行一个 id，支持空行和 `#` 注释；`.csv` 文件会读取每个单元格作为 id。 |
| `--source-task` | 直接指定 dataflow-vuln-scanner 原始 normal task id。可重复，也可逗号分隔。适合不想依赖漏洞平台时调试 replay。 |
| `--source-tasks-file` | source task id 文件。格式同 `--selected-results-file`。 |
| `--auto-expand-source-results` | 使用 `--selected-result` 时，按同一个 source task 查询漏洞平台，把该 source task 的所有结果都计入 baseline expected count，而不是只计入用户勾选的 result。 |
| `--expected-result-count` | 直接使用 `--source-task` 时的 baseline 结果数兜底。若能从源任务 `latest_run.result_count` 读取，则优先使用源任务值；`--skip-source-validation` 时直接使用该值。 |
| `--skip-source-validation` | 跳过 `replay-ready` 和 `get_task` 预检。主要用于 `--source-task + --dry-run` 快速生成 payload 和目录结构；真实 replay 仍会被 dataflow-vuln-scanner 的 `create-evolution` 服务端校验。 |

### REST 与认证

| 选项 | 用法 |
| --- | --- |
| `--dataflow-base-url` | dataflow-vuln-scanner 服务地址。默认 `http://secflow-app-dataflow-vuln-scanner`。本机调试可改为 `http://127.0.0.1:<port>`。 |
| `--dataflow-api-prefix` | dataflow-vuln-scanner API 前缀。默认 `/api/dataflow-vuln-scanner`。 |
| `--vuln-base-url` | 漏洞平台服务地址。使用 `--selected-result` 或 `--auto-expand-source-results` 时需要。默认 `http://secflow-platform-vuln`。 |
| `--vuln-api-prefix` | 漏洞平台 API 前缀。默认 `/api/vuln`。 |
| `--token` | Authorization token。可传纯 token，也可传完整 `Bearer <token>`。若不传，会尝试环境变量 `AUTHORIZATION` 或 `SECFLOW_AUTHORIZATION`。 |
| `--token-file` | 从文件读取 token。适合避免在 shell history 里留下 token。 |
| `--http-timeout` | 单次 REST 请求超时时间，单位秒，默认 `60`。 |

### 实验目录与轮次

| 选项 | 用法 |
| --- | --- |
| `--workspace-root` | 项目文件根目录，默认 `/data/files`。最终项目根为 `<workspace-root>/<project-id>`。本地 smoke test 可设置为 `/tmp/...`。 |
| `--dataflow-subproject-name` | dataflow scanner 文件子项目名，默认 `DATAFLOW_VULN_SCANNER`。一般不需要改。 |
| `--experiment-id` | 实验 id。默认自动生成 `evo-cli-<timestamp>-<suffix>`。指定后可稳定复现实验目录。 |
| `--evolve-agents` | 要进化的 agent，逗号分隔。支持 `pi-worker`、`pi-advisor`，默认二者都进化。示例：`--evolve-agents pi-worker`。 |
| `--max-rounds` | 最大进化轮数，默认 `3`。达到最大轮数后停止。 |
| `--min-rounds` | 最小进化轮数，默认 `1`。只有达到该轮数后，meta evaluator 通过才会提前停止。 |
| `--max-concurrent-source-tasks` | 每轮并发 replay 的 source task 数，默认 `4`。源任务多时可调大，但会增加 scanner 压力。 |
| `--poll-interval-seconds` | 轮询 derived replay task 状态的间隔秒数，默认 `5`。 |
| `--derived-timeout-seconds` | 单个 derived replay task 最大等待秒数，默认 `7200`。超过后 CLI 认为该 replay 超时失败。 |

### Replay 覆盖项

| 选项 | 用法 |
| --- | --- |
| `--profile-id` | 覆盖 replay 使用的 dataflow scan profile id。不传则由源任务或 dataflow-vuln-scanner 默认逻辑决定。 |
| `--model` | 覆盖 replay 使用的模型，例如 `icsl/zai-org/GLM-5`。不传则沿用源任务或服务配置。 |
| `--provider` | 覆盖 provider。通常 model 已包含 provider 时不用传。 |
| `--review-profile` | 覆盖 review profile，例如 `fast`、`balanced`、`audit`。 |
| `--agent-run-timeout-seconds` | 覆盖单次 agent 运行超时秒数。 |
| `--auto-report-vulnerabilities` | 让 replay 自动写入正式漏洞池。默认关闭，避免 evolution replay 污染正式漏洞结果。调试时通常不要打开。 |

### Candidate Memory 与评估

| 选项 | 用法 |
| --- | --- |
| `--seed-from-source-memory` | 默认开启。第一轮复制源任务 agent memory 作为 seed，再写入本轮 evolution candidate memory。 |
| `--no-seed-from-source-memory` | 关闭源 memory seed，第一轮只生成新的 evolution candidate memory。适合验证某条 memory 是否独立生效。 |
| `--memory-note` | 额外追加到每轮 candidate memory 的 markdown 文件。适合把你手写的规则、经验、反例直接注入候选 memory。 |
| `--pass-score-threshold` | meta evaluator 通过所需最低规则分，默认 `800`。 |
| `--max-false-negative-rate` | meta evaluator 允许的最大漏报率，默认 `0.05`。 |
| `--max-false-positive-rate` | meta evaluator 允许的最大误报率，默认 `0.20`。 |

### 运行模式

| 选项 | 用法 |
| --- | --- |
| `--dry-run` | 只生成 candidate memory 和 replay payload，不创建 replay 任务。不能和 `--promote` 同时使用。 |
| `--promote` | 运行结束后，把最佳 round 的 memory 复制到 `promoted-evolution-cli`，并写入 `evolution-memory-mode.json`。 |
| `--disable-memory-mode` | 写入 `mode=shared` 的 memory-mode 文件并退出，用于恢复普通 shared memory。 |
| `--show-memory-mode` | 打印当前项目的 `evolution-memory-mode.json` 并退出。 |
| `-h`, `--help` | 打印命令行帮助和示例。 |

## 调试注意事项

- 源任务必须是 dataflow-vuln-scanner 的 `normal` 任务，除非使用 `--skip-source-validation` 只做 payload 调试。
- replay 会通过 `/tasks/{source_task_id}/create-evolution` 创建 `task_purpose=evolution` 的任务。
- candidate memory 会通过 `agent_state_roots` 注入，可同时注入 `pi-worker` 和 `pi-advisor`。
- meta evaluator 固定在本 CLI 中，不读取候选 `pi-advisor` memory，避免 advisor memory 自我打分。
- v1 只生成 agent memory markdown，不进化 prompts、代码或 skills。

## 服务化接口

本目录里仍保留了服务化实现，适合后续接 UI 或自动调度。调试阶段建议先用 `run_evolution.py`。

REST API 前缀：

- `/api/app/binary-evolution`

自进化 experiment API：

- `POST /evolution/experiments`
- `POST /evolution/experiments/{id}/start`
- `GET /evolution/experiments/{id}`
- `POST /evolution/experiments/{id}/promote`
- `GET /evolution/projects/{project_id}/memory-mode`
- `PATCH /evolution/projects/{project_id}/memory-mode`
