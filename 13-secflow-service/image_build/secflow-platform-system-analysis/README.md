# SecFlow Platform System Analysis

独立系统分析微服务，负责：
- 测试环境自动化分析任务编排
- Prompt 模板管理
- 任务执行结果聚合与报告生成
- 复用 secflow-platform-agent 的节点/helper/AI Agent 会话能力

## Run

```bash
cd 13-secflow-service/image_build/secflow-platform-system-analysis
pip install -r requirements.txt
python -m app.main
```

服务默认端口：`10011`

## API

- 基础前缀：`/api/system-analysis`
- 详细接口见：`doc/API.md`

## CI / Deployment

- GitHub 构建工作流：`.github/workflows/build-secflow-platform-system-analysis-image.yaml`
- 服务目录 k8s 清单：
  - `k8s-configmap.yaml`
  - `k8s-deployment.yaml`
  - `k8s-service.yaml`
- 平台统一部署清单：
  - `13-secflow-service/00-secflow-15-00-platform-system-analysis-configmap.yaml`
  - `13-secflow-service/00-secflow-15-01-platform-system-analysis-deployment.yaml`
  - `13-secflow-service/00-secflow-15-02-platform-system-analysis-service.yaml`
