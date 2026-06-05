---
name: evolution-depth-review
description: 进化策略 — 指导深入性评审角色的审查方向。
---

# 深入性评审 Evolution Strategy — Round 1

## 进化目标

降低审计模式下对间接数据流和路径覆盖不足的漏报

## 评审重点

在深入性评审中，重点关注：
- worker 对每条数据流路径的分析是否足够深入
- 漏洞模式识别是否全面（不仅限于表层模式）
- 是否考虑了边界条件、类型转换、整数溢出等深层问题

## 评分标准

- vuln_pattern_breadth: 漏洞模式广度
- 如果发现分析浅尝辄止，应要求 worker 深入挖掘
