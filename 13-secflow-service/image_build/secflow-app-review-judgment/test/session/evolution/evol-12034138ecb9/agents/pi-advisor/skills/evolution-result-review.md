---
name: evolution-result-review
description: 进化策略 — 指导结果评审角色的审查方向。
---

# 结果评审 Evolution Strategy — Round 1

## 进化目标

降低审计模式下对间接数据流和路径覆盖不足的漏报

## 评审重点

在结果评审（误报检测）中，重点关注：
- 每个 result 的漏洞证据是否充分
- 数据流路径是否真实可达（而非理论上可能）
- 是否存在路径上的隐式校验被忽略

## 评分标准

- 对每个 result 给出 CONFIRMED / LIKELY / UNLIKELY / FALSE_POSITIVE 判定
- 如果证据不足，应要求 worker 补充证据而非直接判为误报
