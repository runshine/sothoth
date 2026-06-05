---
name: evolution-completeness-review
description: 进化策略 — 指导全面性评审角色的审查方向。
---

# 全面性评审 Evolution Strategy — Round 1

## 进化目标

降低审计模式下对间接数据流和路径覆盖不足的漏报

## 评审重点

在全面性评审中，重点关注：
- worker 是否覆盖了所有相关的数据流路径
- 是否有遗漏的函数调用点未被分析
- 输入源到 sink 的路径是否完整追踪

## 评分标准

- coverage: 数据流路径覆盖率
- 如果发现未覆盖的关键路径，应明确指出并要求 worker 补充
