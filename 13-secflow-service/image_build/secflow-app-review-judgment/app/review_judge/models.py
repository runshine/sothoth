"""
评审研判核心模型定义
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    SUSPICIOUS = "suspicious"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ReviewOpinion:
    """评审 Agent 输出的结构化评审意见"""
    # 漏洞真实性判定
    verdict: str  # confirmed / suspicious / false_positive / inconclusive
    verdict_rationale: str  # 判定理由

    # 可达性分析
    reachable: bool
    reachability_analysis: str  # 可达路径分析

    # 置信度
    confidence: str  # high / medium / low
    confidence_rationale: str

    # 严重性评估
    severity: str  # critical / high / medium / low / info
    severity_justification: str

    # 证据质量
    evidence_quality: str  # 对报告中证据链的评估
    evidence_gaps: list[str] = field(default_factory=list)  # 证据缺口

    # 建议
    suggestions: list[str] = field(default_factory=list)
    additional_checks: list[str] = field(default_factory=list)

    # 原始输出
    raw_output: str = ""
    raw_review_log: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "verdict_rationale": self.verdict_rationale,
            "reachable": self.reachable,
            "reachability_analysis": self.reachability_analysis,
            "confidence": self.confidence,
            "confidence_rationale": self.confidence_rationale,
            "severity": self.severity,
            "severity_justification": self.severity_justification,
            "evidence_quality": self.evidence_quality,
            "evidence_gaps": self.evidence_gaps,
            "suggestions": self.suggestions,
            "additional_checks": self.additional_checks,
        }


@dataclass
class JudgmentResult:
    """最终研判结果"""
    verdict: str  # 最终判定
    severity: str  # 最终严重程度
    confidence: str  # 最终置信度

    # Review Agent 意见
    review_opinion: ReviewOpinion

    # Worker Agent 二次判定
    worker_reassessment: str  # Worker 结合原上下文的重新评估
    points_of_disagreement: list[str] = field(default_factory=list)
    points_of_agreement: list[str] = field(default_factory=list)

    # 综合结论
    final_summary: str = ""
    recommended_actions: list[str] = field(default_factory=list)

    # 元信息
    run_name: str = ""
    work_dir: str = ""
    started_at: str = ""
    finished_at: str = ""
    raw_worker_output: str = ""
    raw_worker_log: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "severity": self.severity,
            "confidence": self.confidence,
            "review_opinion": self.review_opinion.to_dict(),
            "worker_reassessment": self.worker_reassessment,
            "points_of_agreement": self.points_of_agreement,
            "points_of_disagreement": self.points_of_disagreement,
            "final_summary": self.final_summary,
            "recommended_actions": self.recommended_actions,
            "run_name": self.run_name,
            "work_dir": self.work_dir,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }