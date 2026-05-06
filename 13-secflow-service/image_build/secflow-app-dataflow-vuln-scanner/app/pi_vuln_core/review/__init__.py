"""review 包导出"""
from app.pi_vuln_core.review.state import ReviewState, FailedResultItem, ResultItemState
from app.pi_vuln_core.review.models import ParsedReviewResult, parse_review_response

__all__ = [
    "ReviewState", "FailedResultItem", "ResultItemState",
    "ParsedReviewResult", "parse_review_response",
    "ReviewScheduler",
    "GlobalReviewExecutor", "ResultReviewExecutor", "ResultReviewFrameworkError",
]


def __getattr__(name: str):
    """Lazy-load orchestration classes to avoid package import cycles."""
    if name == "ReviewScheduler":
        from app.pi_vuln_core.review.scheduler import ReviewScheduler

        return ReviewScheduler
    if name == "GlobalReviewExecutor":
        from app.pi_vuln_core.review.global_review import GlobalReviewExecutor

        return GlobalReviewExecutor
    if name == "ResultReviewExecutor":
        from app.pi_vuln_core.review.result_review import ResultReviewExecutor

        return ResultReviewExecutor
    if name == "ResultReviewFrameworkError":
        from app.pi_vuln_core.review.result_review import ResultReviewFrameworkError

        return ResultReviewFrameworkError
    raise AttributeError(name)
