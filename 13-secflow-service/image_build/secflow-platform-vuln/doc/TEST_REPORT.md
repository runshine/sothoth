# SecFlow 漏洞生命周期编排引擎测试报告

## 1. 测试目标

围绕 `secflow-platform-vuln` 验证：

- 接口实现正确
- 生命周期引擎逻辑稳定
- 人工任务与裁决逻辑正确
- 编排推荐与 `Action` 控制可用
- 本地性能基准稳定
- 集群运行状态健康

## 2. 已执行测试

### 2.1 后端回归测试

执行命令：

```bash
/home/runshine/miniconda3/bin/conda run --no-capture-output -n sothoth \
  pytest 13-secflow-service/image_build/secflow-platform-vuln/tests -q
```

结果：

- `10 passed`

覆盖内容：

- 健康检查
- 服务注册、查询、心跳、注销
- `Case` 创建、详情、时间线
- `Action` mock 派发、回调、重试、取消
- dashboard 总览
- 人工任务创建与状态更新
- 人工裁决与阶段推进
- 自动规则生成 `manual_validation`
- 自动规则生成 `manual_review`
- 推荐动作对活动中的 `service/action` 标记
- 注册中心心跳 `404` 自动重注册

### 2.2 前端校验

执行命令：

```bash
npm -C 13-secflow-service/image_build/secflow-frontend run lint
npm -C 13-secflow-service/image_build/secflow-frontend run build
```

结果：

- `lint` 通过
- `build` 通过

说明：

- 仅保留现有工程的 bundle 体积 warning
- 未发现漏洞引擎工作台新增的构建错误

### 2.3 测速测试

执行命令：

```bash
/home/runshine/miniconda3/bin/conda run --no-capture-output -n sothoth \
  python 13-secflow-service/image_build/secflow-platform-vuln/tests/benchmark_vuln_local.py
```

结果：

- 5 个基准场景全部 `0 error`

详见：

- [PERFORMANCE_PLAN.md](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-vuln/doc/PERFORMANCE_PLAN.md)
- [PERFORMANCE_REPORT.md](/home/runshine/CLionProjects/sothoth/13-secflow-service/image_build/secflow-platform-vuln/doc/PERFORMANCE_REPORT.md)

### 2.4 集群运行检查

检查项：

- Deployment Ready
- Ingress 健康访问
- Pod 日志

结果：

- `secflow-platform-vuln` 当前集群状态为 `2/2`
- `/api/vuln/health` 正常
- `/api/vuln/ready` 正常

## 3. 发现的问题与处理

发现 1：

- 部署中的 `vuln` 模块日志存在周期性 `POST /api/menu/heartbeat/... -> 404`

定位：

- `app/services/registry.py` 的心跳逻辑没有像平台其他微服务那样在 `404` 时自动重新注册

处理：

- 已修改心跳逻辑
- 当 menu 心跳返回 `404` 时自动执行 `register()`
- 同时补充了回归测试 `test_registry_heartbeat_reregisters_on_404`

发现 2：

- 首版本地压测脚本日志噪声过大，不适合作为基准输出

处理：

- 已关闭 `httpx/httpcore` 的 INFO 级日志
- 已把本地 sqlite 基准的写入并发调整到更合理规模
- 重新执行后结果稳定

## 4. 当前结论

在当前代码状态下：

- 回归测试通过
- 测速测试通过
- 集群健康检查通过
- 已发现并修复的逻辑问题已通过测试锁定

当前没有发现新的阻塞性问题。

## 5. 后续建议

- 将 `registry.py` 修复发布到集群，清理 menu heartbeat 的 404 日志
- 继续补对象存储与附件接口测试
- 在 k8s 环境做生产级压测
- 为前端工作台补交互自动化测试
