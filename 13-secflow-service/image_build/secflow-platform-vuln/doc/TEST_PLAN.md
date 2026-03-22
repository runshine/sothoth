# SecFlow 漏洞生命周期编排引擎测试方案

## 1. 测试目标

验证 `secflow-platform-vuln` 当前实现满足以下目标：

- 服务在 `conda sothoth` 环境可正常导入和启动
- 服务注册、Case、Action、Result、人工任务形成最小闭环
- 自动推进规则不会破坏基础生命周期
- 前端漏洞引擎工作台可以通过类型检查和生产构建
- GitHub Actions 能构建 x64/aarch64 镜像
- k8s 中服务、探针、Ingress、滚动升级正常

## 2. 测试分层

### 2.1 后端接口与烟雾测试

重点覆盖：

- 健康检查
- 服务注册与查询
- Case 创建、详情、时间线
- Action mock 派发、回调、控制
- 项目级 dashboard
- 人工任务创建、状态更新
- 人工裁决
- 自动规则触发后的人工作业生成
- 项目级 Action 队列

测试方式：

- `sqlite + StaticPool`
- 覆盖 auth/project 访问控制依赖
- 通过 `pytest` 做接口级 smoke test

### 2.2 前端构建测试

- `npm run lint`
- `npm run build`

验证内容：

- `vuln` API 类型和调用链正常
- 工作台多视图组件可正常构建
- 组件拆分后不引入 TypeScript 错误

### 2.3 环境导入测试

在 `sothoth` conda 环境验证：

- 配置加载
- FastAPI 应用导入
- 依赖初始化流程

### 2.4 CI 构建测试

验证 GitHub Actions：

- `build-secflow-platform-vuln-image`
- `build-secflow-frontend-image`

要求：

- amd64 构建成功
- arm64 构建成功
- manifest 合并成功

### 2.5 k8s 运行时测试

验证：

- Deployment 滚动发布成功
- 新 Pod 镜像正确
- `health` / `ready` 探针通过
- Ingress 路由可访问
- 事件和日志无明显错误

## 3. 当前已执行测试

### 后端

执行命令：

```bash
conda run --no-capture-output -n sothoth pytest 13-secflow-service/image_build/secflow-platform-vuln/tests -q
```

当前结果：

- `6 passed`

### 前端

执行命令：

```bash
npm -C 13-secflow-service/image_build/secflow-frontend run lint
npm -C 13-secflow-service/image_build/secflow-frontend run build
```

当前结果：

- lint 通过
- build 通过
- 仅保留现有工程的大 bundle warning

### GitHub Actions

最近一次已验证通过的构建：

- `build-secflow-platform-vuln-image`
- `build-secflow-frontend-image`

两条流水都完成了：

- amd64
- arm64
- multi-arch manifest

### 集群验证

已验证：

- `secflow-platform-vuln` 使用 `ghcr.io/runshine/secflow-platform-vuln:20260322`
- `secflow-platform-frontend` 使用 `ghcr.io/runshine/secflow-frontend:20260322`
- 两个 Deployment 均已 Ready
- `GET /api/vuln/health` 返回正常
- `GET /api/frontend/health` 返回正常

## 4. 建议继续补充的测试

- 自动编排推荐规则的更细粒度单元测试
- 更多 `decision_status` 和阶段回退场景
- 真实附件上传/存储测试
- 更复杂的 capability 路由选择测试
- Playwright 或 Cypress 前端交互测试
- k8s 发布后自动健康回归测试
