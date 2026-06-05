---
name: evolution-result-review
description: 进化策略 — 指导结果评审角色的审查方向。
---

# 结果评审 Evolution Strategy — Round 1

## 进化目标

降低误报率，对触发条件严苛或者不确定模块外有无检查的漏洞提判定为误报，提高评审通过标准

## 评审重点

在结果评审（误报检测）中，重点关注：
- 每个 result 的漏洞证据是否充分
- 数据流路径是否真实可达（而非理论上可能）
- 是否存在路径上的隐式校验被忽略

## 评分标准

- 对每个 result 给出 CONFIRMED / LIKELY / UNLIKELY / FALSE_POSITIVE 判定
- 如果证据不足，应要求 worker 补充证据而非直接判为误报
