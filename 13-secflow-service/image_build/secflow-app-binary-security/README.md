# secflow-app-binary-security

Release note: 2026-06-18 compatibility sweep for task manager helper facades and worker/reducer runtime recovery.

统一的二进制软件包安全编排微服务，负责按固定阶段顺序调用：

`firmware-unpacker -> system-analyse -> binary-to-source -> entry-analyse -> dataflow-vuln-scan`

## 主要能力

- 项目级任务统一入口
- 认证与项目权限校验
- 菜单注册与心跳
- 数据库持久化总任务、阶段运行、阶段子任务、事件流
- 阶段顺序固定，阶段内按并发上限并行
- 默认局部失败不中止整条流水线
- 聚合统一产物目录与时间线

## Pipeline Modes

- `barrier`：默认模式，所有阶段按固定顺序推进；只有上一个阶段整体完成后，才会进入下一个阶段。
- `mixed_streaming`：混合流式模式，前半段仍然按阶段屏障推进，后半段改为按单个产物逐级下钻。

当前支持的混合流式拆分方式：

`firmware-unpacker -> system-analyse -> binary-to-source`

保持为阶段屏障模式；

`entry-analyse -> dataflow-vuln-scan`

保持阶段顺序，但以 item 为单位流式推进。

## Mixed Streaming 行为

- `binary-to-source` 产出单个结果后，可立即为对应模块创建 `entry-analyse` 子任务。
- 单个 `entry-analyse` 完成后，可立即为其派生 `dataflow-vuln-scan` 子任务。
- 下游任务输入来自上游 item 结果及其聚合产物，不需要等待同阶段全部模块完成。
- 并发控制仍然只服从总阶段并发上限；下层排队由下游服务自身负责。

## DFA 路径契约

为了避免 `entry-analyse`、`system-analyse`、`dataflow-vuln-scan` 之间混用“模块目录”和“源码根目录”，编排器统一遵守下面的定义：

- `module_input_path`
  - 含义：模块描述目录
  - 来源：`system-analyse/modules/<module>`、B2S 模块目录、或其他包含 `files.list` 的模块输入目录
  - 用途：供入口分析、人工排障、前端展示模块范围
- `source_root_path`
  - 含义：真实源码根目录
  - 来源：
    - `source` 任务：原始源码输入根
    - `binary_module / B2S` 任务：智能体逆向优化后的源码产物根
  - 用途：供 DFA 提取函数体、定位 `source_file`
- `source_file`
  - 含义：相对于 `source_root_path` 的规范化相对路径
  - 约束：不得是绝对路径，不得越界到 `source_root_path` 外
- `definition_kind`
  - `definition` 才允许创建 DFA 子任务
  - `declaration/unknown` 默认只保留在 entry 结果中，不派生 DFA

这意味着：

- `entry-analyse` 允许 `input_path != source_path`
- `dataflow-vuln-scan` 不再允许只靠 `input_path` 猜源码根
- Binary Security 在创建 DFA 子任务时，必须显式同时传 `module_input_path` 和 `source_root_path`

## 状态语义

- 混合流式尾部阶段激活后，任务会在 `entry-analyse / dataflow-vuln-scan` 之间自动推进。
- 某个尾部阶段即使当前没有待执行 item，也会保留已有的 `failed`、`downstream_missing` 等阶段状态，而不是一律回退为 `pending`。
- 任务详情、阶段摘要和手工操作面板会把“尾部仍在自动推进”的任务视作运行中，避免错误暴露 `continue` / `retry`。

## 重试语义

- 在 `mixed_streaming` 模式下，尾部阶段失败项重试采用 lineage 定向清理，而不是整阶段清空。
- 重试 `entry-analyse` item 时，只清理它派生出的 `dataflow-vuln-scan` 后代。
- 这样可以保留其他模块已经完成的分析结果，减少重复计算。

## 配置

在 `runtime_policy` 中配置：

```yaml
runtime_policy:
  pipeline_mode: barrier   # barrier | mixed_streaming
  max_stage_parallelism: 4
```

- `pipeline_mode` 当前默认值为 `barrier`，便于与现网行为保持兼容。
- 切换到 `mixed_streaming` 后，仅影响尾部三个分析阶段的推进方式，不改变前置阶段顺序。

## 验证覆盖

- 生命周期：阶段完成后切换到流式尾部的 reducer 序列。
- 调度行为：`binary-to-source -> entry-analyse -> dataflow-vuln-scan` 的逐级派生。
- 状态同步：任务详情、阶段摘要、手工操作状态与尾部阶段快照一致。
- 重试逻辑：尾部失败项按 lineage 清理后代结果，避免整阶段回滚。

## 历史数据归一

如果库中仍存在旧阶段名或旧下游服务名称，可执行一次性归一脚本（镜像内路径）：

```bash
python /app/scripts/normalize_legacy_dataflow_names.py
```

脚本会把以下旧值统一到当前规范：

- `dataflow_analysis` -> `dataflow_vuln_scan`
- `vuln_scan` -> `dataflow_vuln_scan`
- `dataflow_analyse` -> `dataflow_vuln_scan`
- `dataflow_vuln_scanner` -> `dataflow_vuln_scan`

## 灰度与验收

推荐按以下顺序灰度上线 `mixed_streaming`：

1. 保持 `runtime_policy.pipeline_mode: barrier` 部署新版本，先验证服务启动、路由、worker、reducer 正常。
2. 选择单个低风险项目，通过项目级配置切换 `pipeline_mode: mixed_streaming`，不要直接改全局默认值。
3. 先跑一批源码任务，重点观察 `entry-analyse / dataflow-vuln-scan` 是否出现按 item 流式推进。
4. 验证任务详情、`stage-items`、`orchestration-observability` 三个视图对尾部运行态与失败态的展示是否一致。
5. 验证 `retry` 与 `retry_failed_items` 在尾部 `failed`、`downstream_missing`、`partial_success` 场景下行为符合预期。
6. 灰度稳定后，再评估是否把默认值从 `barrier` 调整为 `mixed_streaming`。

建议验收项：

- barrier 任务行为与旧版本一致。
- mixed_streaming 任务中，`binary-to-source` 完成后无需等待全量模块即可出现 `entry-analyse` item。
- tail 失败时，异常原因、overview node、手工操作面板保持一致。
- tail 成功 / 失败 / partial_success 三种终局均可稳定收敛。
- 项目级 `pipeline_mode`、任务级 override、默认配置三层优先级符合预期。

建议回滚策略：

- 优先把项目级 `pipeline_mode` 切回 `barrier`。
- 如需服务级回滚，恢复 `config.yaml` 中 `runtime_policy.pipeline_mode: barrier` 并重新发布。
- 已经运行中的 mixed_streaming 任务允许自然收敛；如出现异常，可结合 `retry` / `retry_failed_items` 或取消任务处理。

## API

```text
GET  /api/app/binary-security/health
GET  /api/app/binary-security/ready
GET  /api/app/binary-security/projects/{project_id}/tasks
POST /api/app/binary-security/projects/{project_id}/tasks/prepare
POST /api/app/binary-security/projects/{project_id}/tasks
GET  /api/app/binary-security/projects/{project_id}/tasks/{task_id}
GET  /api/app/binary-security/projects/{project_id}/tasks/{task_id}/timeline
GET  /api/app/binary-security/projects/{project_id}/tasks/{task_id}/artifacts
POST /api/app/binary-security/projects/{project_id}/tasks/{task_id}/cancel
POST /api/app/binary-security/projects/{project_id}/tasks/{task_id}/retry
GET  /api/app/binary-security/config
PUT  /api/app/binary-security/config
```

## 工作目录

默认工作目录：

```text
/data/files/{project_id}/app/secflow-app-binary-security/{task_id}/
```

目录结构：

```text
input/
runtime/
artifacts/unpack/
artifacts/system-analysis/
artifacts/b2s/
artifacts/entry/
artifacts/dataflow/
artifacts/vuln/
summary/
logs/
```

## 运行

```bash
pip install -r requirements.txt
python -m app.main
```

或：

```bash
docker build -t secflow-app-binary-security .
docker run --rm -p 8080:8080 -v /data:/data secflow-app-binary-security
```
