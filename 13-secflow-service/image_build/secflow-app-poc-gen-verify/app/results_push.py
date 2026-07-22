"""主动推送漏洞判定结果到平台（契约接口4，Contract v2.3 §5.2）。

PUSH 为主、PULL 兜底：worker 完成 poc 任务提交终态后，应立即通过本模块推送
契约结果到平台 ``/api/vuln/internal/vuln-confirm/results/push``，把前端从
「确认中」到终态的延迟从最长 60s 降到秒级。

设计：
- best-effort：任何 HTTP / 构造异常都只记录 warning，不向 worker 主链路抛出。
  失败时下一轮兜底 polling（60s 内）会拉到结果，平台不要求推送必达（§5.2.4）。
- 重试：传输层（TCP / 5xx）指数退避 3 次；4xx / 404 不重试（§5.2.4）。
- 仅对契约任务（vuln_id 非空）推送；前端任务 vuln_id 为 NULL，build_push_payload
  返回 None，推送跳过。
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import get_engine_config
from app.contract import (
    CONTRACT_STATUS_DONE,
    CONTRACT_STATUS_RUNNING,
    build_contract_response,
    contract_classification,
    map_contract_outcome,
)
from app.db import get_db
from app.db.models import AppPocTask

logger = logging.getLogger("poc.results_push")

DEFAULT_PUSH_TIMEOUT_SECONDS = 5.0
MAX_HTTP_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 1.0  # 1s, 2s, 4s


class PushResult:
    """轻量结果对象（避免引入 pydantic 依赖）。"""

    def __init__(self, *, ok: bool, skipped: bool = False, attempts: int = 0,
                 status_code: int | None = None, error: str | None = None) -> None:
        self.ok = ok
        self.skipped = skipped
        self.attempts = attempts
        self.status_code = status_code
        self.error = error

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok, "skipped": self.skipped, "attempts": self.attempts,
            "status_code": self.status_code, "error": self.error,
        }


def _is_retryable_status(status_code: int) -> bool:
    return status_code == 429 or status_code >= 500


def push_results(payloads: list[dict[str, Any]]) -> PushResult:
    """推送一批契约结果。

    请求体固定为 ``{"engine_name": cfg.name, "results": payloads}``。
    ``engine.results_push_url`` 为空字符串时跳过（测试 / 逃生阀）。
    """
    cfg = get_engine_config()
    url = (cfg.results_push_url or "").strip()
    if not url:
        logger.info("results push skipped: engine.results_push_url is empty")
        return PushResult(ok=True, skipped=True)
    if not payloads:
        return PushResult(ok=True, skipped=True)

    body = {"engine_name": cfg.name, "results": payloads}
    timeout = max(0.1, cfg.results_push_timeout_seconds)
    attempts = 0
    last_status: int | None = None
    last_error: str | None = None

    import time
    for attempt in range(1, MAX_HTTP_ATTEMPTS + 1):
        attempts = attempt
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(url, json=body)
            last_status = resp.status_code
            last_error = None
            if 200 <= resp.status_code < 300:
                return PushResult(ok=True, attempts=attempts, status_code=resp.status_code)
            last_error = resp.text[:500]
            # 404 = engine_not_registered；4xx / 404 不重试（§5.2.4）
            if not _is_retryable_status(resp.status_code) or attempt >= MAX_HTTP_ATTEMPTS:
                logger.warning(
                    "results push failed: status=%s attempts=%s body=%s",
                    resp.status_code, attempts, last_error,
                )
                return PushResult(ok=False, attempts=attempts, status_code=resp.status_code, error=last_error)
        except (httpx.HTTPError, OSError) as exc:
            last_error = str(exc)
            if attempt >= MAX_HTTP_ATTEMPTS:
                logger.warning("results push network error: attempts=%s error=%s", attempts, exc)
                return PushResult(ok=False, attempts=attempts, error=last_error)
        except Exception as exc:  # defensive: never break worker path
            logger.warning("results push unexpected error: %s", exc, exc_info=True)
            return PushResult(ok=False, attempts=attempts, status_code=last_status, error=str(exc))
        # 指数退避（仅对可重试错误）
        if attempt < MAX_HTTP_ATTEMPTS:
            time.sleep(BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)))

    logger.warning("results push failed after retries: status=%s error=%s", last_status, last_error)
    return PushResult(ok=False, attempts=attempts, status_code=last_status, error=last_error)


def build_push_payload(row: AppPocTask) -> dict[str, Any] | None:
    """构造主动 push 的中文契约 payload。

    - 仅契约任务（vuln_id 非空）可推送；前端任务返回 None。
    - 仅 running / 终态（已完成 / 失败）推送；pending 不推。
    """
    if not row.vuln_id:
        return None
    status, verdict, reason = map_contract_outcome(row)
    if status not in {CONTRACT_STATUS_RUNNING, CONTRACT_STATUS_DONE, "失败"}:
        return None
    classification = contract_classification(row, status, verdict)
    return build_contract_response(row.vuln_id, status, verdict, reason, classification)


def _load_row(task_id: str) -> AppPocTask | None:
    db_gen = get_db()
    db = next(db_gen)
    try:
        return (
            db.query(AppPocTask)
            .filter(AppPocTask.task_id == task_id, AppPocTask.is_deleted.is_(False))
            .first()
        )
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass


def push_task_running(task_id: str) -> PushResult:
    """任务 claim 后推送「进行中」（仅契约任务）。"""
    row = _load_row(task_id)
    if row is None:
        return PushResult(ok=True, skipped=True)
    payload = build_push_payload(row)
    if payload is None or payload.get("状态") != CONTRACT_STATUS_RUNNING:
        return PushResult(ok=True, skipped=True)
    return push_results([payload])


def push_task_terminal(task_id: str) -> PushResult:
    """任务终态提交后推送终态结果（已完成 / 失败）；仅契约任务。

    worker 在 _commit_terminal_retry 成功后调用本函数。best-effort，失败不重投。
    """
    row = _load_row(task_id)
    if row is None:
        logger.warning("results push skipped: task not found task_id=%s", task_id)
        return PushResult(ok=True, skipped=True)
    payload = build_push_payload(row)
    if payload is None:
        return PushResult(ok=True, skipped=True)
    # 仅推送终态（已完成 / 失败）；进行中走 push_task_running。
    if payload.get("状态") == CONTRACT_STATUS_RUNNING:
        return PushResult(ok=True, skipped=True)
    return push_results([payload])
