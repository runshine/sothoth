# SecFlow 漏洞生命周期编排引擎测试方案

## 1. 测试目标

验证 `secflow-platform-vuln` 在第一期范围内满足以下能力：

- 服务可在目标运行环境中成功导入和启动
- 服务注册、Case 创建、Action 回调、时间线查询形成闭环
- 前端新增漏洞引擎工作台页面可成功编译
- k8s 部署清单结构完整，适配多实例共享 PVC
- GitHub Actions 多架构构建链路可触发并产出镜像

## 2. 测试分层

### 2.1 静态与结构测试

- Python 语法检查
- TypeScript 类型检查
- GitHub Actions 工作流结构检查
- k8s YAML 基本命名与资源结构检查

### 2.2 单元与接口烟雾测试

后端重点覆盖：

- `GET /api/vuln/health`
- `POST /api/vuln/services/register`
- `GET /api/vuln/services`
- `POST /api/vuln/cases`
- `GET /api/vuln/cases/{id}`
- `GET /api/vuln/cases/{id}/timeline`
- `POST /api/vuln/actions/{id}/callback`

测试方式：

- 使用 sqlite + `StaticPool` 构造轻量测试数据库
- 对认证和项目访问做可控 override
- 验证生命周期的最小闭环

### 2.3 前端构建测试

- `npm run lint`
- `npm run build`

验证：

- 新增 `vuln` API 接口未破坏现有工程
- 漏洞引擎工作台页面类型和构建通过

### 2.4 环境与运行时测试

- 在 `conda sothoth` 环境中进行真实导入
- 验证配置文件与 FastAPI 应用对象可正常加载

### 2.5 集群验证

部署后验证：

- Pod Ready/Running
- Service 正常暴露
- Ingress 路由配置正确
- `health` 与 `ready` 接口返回正常

## 3. 当前已执行测试

### 后端

- `conda run -n sothoth python -m py_compile ...`
- `conda run -n sothoth pytest 13-secflow-service/image_build/secflow-platform-vuln/tests -q`

结果：

- 4 个 smoke tests 全部通过

### 前端

- `npm -C 13-secflow-service/image_build/secflow-frontend run lint`
- `npm -C 13-secflow-service/image_build/secflow-frontend run build`

结果：

- lint 通过
- build 通过

### 运行环境

- 在 `sothoth` conda 环境中验证配置导入和 `app.main:app` 导入成功

## 4. 后续建议补充测试

- 服务注册心跳与超时摘除测试
- 生命周期阶段推进规则测试
- Action 自动派发测试
- Artifact 存储路径与元数据测试
- 前端交互测试
- k8s 集群联调自动化测试
