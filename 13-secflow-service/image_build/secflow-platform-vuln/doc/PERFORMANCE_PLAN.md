# SecFlow 漏洞生命周期编排引擎测速方案

## 1. 目标

围绕 `secflow-platform-vuln` 当前实现，验证：

- 基础读接口在项目级工作台场景下是否足够轻量
- `Case` 创建和列表查询在中等并发下是否稳定
- dashboard 聚合接口在已有数据下是否能稳定返回
- 最小状态流转链路在连续执行时是否会出现逻辑错误
- 压测过程中是否会暴露隐藏的接口正确性问题

## 2. 测试范围

### 2.1 读路径

- `GET /api/vuln/health`
- `GET /api/vuln/cases`
- `GET /api/vuln/cases/ops/dashboard/overview`

### 2.2 写路径

- `POST /api/vuln/cases`

### 2.3 状态流转路径

- `POST /api/vuln/cases/{case_id}/actions/dispatch`
- `POST /api/vuln/actions/{action_id}/callback`
- `GET /api/vuln/cases/{case_id}`

## 3. 测试方法

采用本地 ASGI 直连压测：

- 不经过网络和 ingress
- 使用 `httpx.ASGITransport`
- 使用临时 sqlite 文件数据库
- 对 auth/project 依赖做 override

这样能先验证应用本身的：

- 接口正确性
- 并发稳定性
- 逻辑一致性
- 大致响应时间

## 4. 基准场景

### 场景 A：健康检查高频读取

- 请求数：200
- 并发：25
- 目标：验证基础健康检查足够轻量

### 场景 B：Case 创建突发写入

- 请求数：80
- 并发：10
- 目标：验证基础写入能力和阶段初始化逻辑

### 场景 C：Case 列表聚合读取

- 请求数：120
- 并发：20
- 目标：验证工作台列表页基础性能

### 场景 D：Dashboard 聚合读取

- 请求数：120
- 并发：20
- 目标：验证总览聚合接口的稳定性

### 场景 E：端到端状态流转

- 顺序执行 30 次：
  - 创建 Case
  - 派发 Action
  - 回调 Result
  - 读取详情
- 目标：验证最小生命周期闭环的正确性和时延

## 5. 输出指标

每个场景输出：

- 总请求数
- 并发数
- 总耗时
- 吞吐量 `RPS`
- 平均耗时 `avg_ms`
- `p95_ms`
- `max_ms`
- 错误数
- 错误样例

## 6. 判定标准

当前阶段以“稳定、无错、逻辑正确”为主：

- 所有场景错误数应为 `0`
- 不应出现状态推进异常
- 不应出现重复任务、数据错乱、接口 5xx
- 工作台核心接口在中等并发下应能稳定返回

## 7. 当前执行命令

```bash
/home/runshine/miniconda3/bin/conda run --no-capture-output -n sothoth \
  python 13-secflow-service/image_build/secflow-platform-vuln/tests/benchmark_vuln_local.py
```
