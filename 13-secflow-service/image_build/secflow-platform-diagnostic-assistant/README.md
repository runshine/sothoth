# Diagnostic Assistant

独立新增的系统管理后端微服务骨架，不修改任何现有子模块代码。

当前实现包含：

- FastAPI 服务
- 复用平台认证服务校验管理员身份
- SQLite 会话/消息/agent run/trace/audit 持久化
- 诊断助手服务作为薄代理，转发到现有 `agent-helper` 的 `/api/ai-agents/*`
- `GET /api/diagnostic-assistant/agents`
- `POST /api/diagnostic-assistant/runs/stream`
- `GET /api/diagnostic-assistant/sessions/{id}/runs`
- `GET /api/diagnostic-assistant/runs/{id}/events`

## 环境变量

- `SERVICE_YAML`：配置文件路径，默认 `/app/service.yaml`

## 本地运行

```bash
cd 13-secflow-service/image_build/secflow-platform-diagnostic-assistant
cp service.yaml.example service.yaml
uvicorn main:app --reload --port 8080
```

## 关键约束

- 不内置大模型 key
- agent 运行时配置沿用 `agent-helper` 自身配置
- 诊断助手服务只做平台鉴权、会话映射、运行审计与轨迹展示
