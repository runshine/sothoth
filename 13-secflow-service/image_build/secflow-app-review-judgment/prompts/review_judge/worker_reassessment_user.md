# 研判任务

一位独立的评审专家对这你发现的漏洞疑点进行了审查并给出了以下反馈。
请基于你原始的完整分析上下文（你之前读取过的所有源码、数据流报告等都在你的会话历史中可访问）
和评审专家的反馈，进行二次判定和分析。

## 评审专家反馈

**判定**: {verdict}
**理由**: {verdict_rationale}

**可达性**: {reachability}
**分析**: {reachability_analysis}

**置信度**: {confidence}
**理由**: {confidence_rationale}

**严重程度**: {severity}
**依据**: {severity_justification}

**证据质量**: {evidence_quality}
**证据缺口**: {evidence_gaps}

**建议**: {suggestions}

**额外检查**: {additional_checks}

## 你的任务

{task_points}

## 输出格式

请以 JSON 格式输出你的最终研判结果：

```json
{{
  "final_verdict": "confirmed|suspicious|false_positive|inconclusive",
  "reassessment": "你的重新评估分析...",
  "final_severity": "critical|high|medium|low|info",
  "final_confidence": "high|medium|low",
  "points_of_agreement": ["同意评审的哪些观点..."],
  "points_of_disagreement": ["不同意评审的哪些观点，并说明原因..."],
  "final_summary": "综合结论...",
  "recommended_actions": ["建议的后续动作..."]
}}
```