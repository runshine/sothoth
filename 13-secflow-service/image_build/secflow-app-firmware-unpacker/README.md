# SecFlow Firmware Unpacker

AgentFlow-only 固件解包入口。当前版本不提供 REST API、任务数据库、Worker 心跳或平台注册，只运行本地 AgentFlow pipeline。

## 运行

```bash
FIRMWARE_PATH=/path/to/firmware.bin \
OUTPUT_PATH=/path/to/output \
RUN_PATH=/path/to/run \
UNPACKER_TOOLS_DIR=/path/to/tools \
python -m app.cli
```

也可以使用镜像入口：

```bash
docker build -t secflow-app-firmware-unpacker .
docker run --rm \
  -e FIRMWARE_PATH=/data/input/fw.bin \
  -e OUTPUT_PATH=/data/output \
  -e RUN_PATH=/data/run \
  -v /host/data:/data \
  secflow-app-firmware-unpacker
```

## 配置

配置文件默认为 `config.yaml`，也可通过 `CONFIG_PATH` 或 `FIRMWARE_UNPACKER_CONFIG` 指定。保留的配置只有：

- `agentflow`: run 目录、并发、节点超时、worktree 和图优化配置
- `logging`: 日志级别和格式

常用环境变量：

- `FIRMWARE_PATH`: 固件文件路径
- `OUTPUT_PATH` 或 `FIRMWARE_OUTPUT`: 解包输出目录
- `RUN_PATH`: 阶段日志目录
- `UNPACKER_TOOLS_DIR`: 可复用 skill 目录
- `AGENTFLOW_RUNS_DIR`: AgentFlow run store 目录
- `AGENTFLOW_MAX_CONCURRENT_RUNS`: AgentFlow 并发
- `AGENTFLOW_NODE_TIMEOUT_SECONDS`: Python 校验节点超时基准
- `MAX_RETRIES` 或 `AGENTFLOW_MAX_ITERATIONS`: pipeline 最大重试轮数

## 代码结构

- `app/cli.py`: AgentFlow-only 命令行入口，负责配置读取、图装配、pipeline 提交、结果汇总和 token/run artifact 处理
- `app/pipeline_stages/*/`: 各 Python 阶段包，每个阶段的实现和私有依赖就近放置
- `app/pipeline_stages/s01_preprocess/engine.py`: 确定性预处理实现
- `app/pipeline_stages/s02_feature_match/features.py`: 固件特征提取
- `app/pipeline_stages/s02_feature_match/skill_store.py`: skill 匹配逻辑
- `app/pipeline_stages/s09_finalize/skill_store.py`: skill 生成和晋级逻辑
- `app/agent/defs.py`: pi agent 定义路径和 frontmatter 解析
- `app/agent/**`: pi agent system prompts 和 prompt 模板

离线回归评测：

```bash
scripts/agentflow_regression_eval.py --manifest plan/agentflow-regression-samples.json
```
