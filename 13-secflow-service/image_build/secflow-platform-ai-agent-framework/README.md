# SecFlow Platform AI Agent Framework

面向漏洞挖掘与验证场景的多智能体 REST 工作流服务。

核心特性：
- 单文件 JSON 配置
- 原子工作流 + 组合工作流
- 插件化 pre/post 阶段
- 多智能体 runtime 适配
- Markdown + JSON 双产物
- FastAPI + MySQL 持久化
- Trigger Task + Execution 异步执行
- MySQL lease / owner 多 POD 抢占式调度

## Run Service

```bash
cd 13-secflow-service/image_build/secflow-platform-ai-agent-framework
pip install -r requirements.txt
python -m app.main
```

## Project Layout

- `app/`: 核心框架代码
- `plugins/`: 外部插件示例
- `examples/`: 示例输入
- `tests/`: 自动化测试

## Config

仓库根目录包含两类配置：
- `config.yaml`：服务配置，包含数据库、认证、注册中心、调度器和工作目录等参数。
- `config.json`：示例工作流 definition JSON，可通过 REST API 入库后启用。

默认 definition 提供了一个可直接运行的 mock 漏洞流水线示例：
- 7 段组合工作流
- 4 种基础智能体类型
- 统一 next task generator
- 示例 pre/post 插件

## API

服务默认暴露前缀 `/api/ai-agent-framework`，提供：
- `workflow-definitions`：工作流定义 CRUD、版本、启停管理
- `trigger-tasks`：任务触发、取消、重试
- `executions`：执行详情、事件、工件查询
- `scheduler/workers`：多 POD worker 状态和 drain/activate 控制

## Docker

```bash
docker build -t secflow-platform-ai-agent-framework .
docker run --rm -p 8080:8080 \
  -e CONFIG_PATH=/app/config.yaml \
  secflow-platform-ai-agent-framework
```
