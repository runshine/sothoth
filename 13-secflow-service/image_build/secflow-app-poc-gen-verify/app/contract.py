"""漏洞判定引擎契约适配层（Contract v2.3）。

薄翻译层：把平台 intake 请求（接口1）映射为现有 ``task_service.create_contract_task``
（INSERT 一行 pending → 调度器泵到 Celery → worker 跑 poc CLI），把内部
``task.status`` / ``poc_path`` 映射为契约中文 schema（接口1响应 / 接口2响应元素 /
接口4推送元素）。

设计原则（KISS）：
- 不改任务状态机、不改 poc CLI 调用链。
- 仅做 schema 翻译 + 入站路由 + 出站映射。
- 未知字段一律忽略（契约 §4.1 / §9.2 允许）。

契约端点路径由 ``EngineConfig.endpoint_prefix`` 决定（默认
``/api/app/poc-gen-verify/intake``），平台管理员注册时把 ``{engine_endpoint}``
指向该前缀：
  接口1  POST {endpoint_prefix}
  接口2  POST {endpoint_prefix}/results/batch
  接口5  POST {endpoint_prefix}/results/confirmed

状态映射（内部 task.status + poc_path → 契约 状态/结果）：
  pending                                          → 等待中 / null
  running                                          → 进行中 / null
  succeeded + poc_path="a"（GDB 触发成功）          → 已完成 / 是
  succeeded + poc_path="b"（证伪/不可达）           → 已完成 / 不是
  succeeded + poc_path=None（未达 Stage2）          → 已完成 / 不可证
  failed / timeout / cancelled                    → 失败 / null
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.config import get_engine_config
from app.db import get_db
from app.db.models import AppPocTask

logger = logging.getLogger("poc.contract")

# ────────────────────────── 状态 / 结果映射 ──────────────────────────

CONTRACT_STATUS_WAITING = "等待中"
CONTRACT_STATUS_RUNNING = "进行中"
CONTRACT_STATUS_DONE = "已完成"
CONTRACT_STATUS_FAILED = "失败"

# 契约终态：已完成 / 失败均为终态
TERMINAL_CONTRACT_STATUS = {CONTRACT_STATUS_DONE, CONTRACT_STATUS_FAILED}

BEIJING_TZ = timezone(timedelta(hours=8))


def map_status(task_status: str) -> str:
    """内部 task.status → 契约「状态」枚举（非终态语义见模块 docstring）。"""
    if task_status in ("succeeded",):
        return CONTRACT_STATUS_DONE
    if task_status == "running":
        return CONTRACT_STATUS_RUNNING
    if task_status == "pending":
        return CONTRACT_STATUS_WAITING
    # failed / timeout / cancelled → 失败（引擎内部无法得出结论）
    return CONTRACT_STATUS_FAILED


def _poc_path(row: AppPocTask) -> Optional[str]:
    stages = row.stages_json
    if isinstance(stages, dict):
        pp = stages.get("poc_path")
        if pp in ("a", "b"):
            return pp
    return None


def map_contract_outcome(row: AppPocTask) -> tuple[str, str | None, str | None]:
    """内部 task + poc_path → 契约 (状态, 结果, 理由)。

    非终态 / 失败时 结果=None。理由仅在终态有意义时填写。
    """
    status = map_status(row.status or "")
    if status == CONTRACT_STATUS_WAITING or status == CONTRACT_STATUS_RUNNING:
        return status, None, None

    if status == CONTRACT_STATUS_FAILED:
        reason = (row.error or "PoC 执行失败")[:8000] if row.error else "PoC 执行失败"
        # 失败状态契约要求 结果=None
        return CONTRACT_STATUS_FAILED, None, reason

    # succeeded → 已完成，按 poc_path 决定 结果
    pp = _poc_path(row)
    if pp == "a":
        return CONTRACT_STATUS_DONE, "是", _build_reason_a(row)
    if pp == "b":
        return CONTRACT_STATUS_DONE, "不是", _build_reason_b(row)
    # succeeded 但无 Stage2 结论 → 不可证
    return CONTRACT_STATUS_DONE, "不可证", _build_reason_inconclusive(row)


def _build_reason_a(row: AppPocTask) -> str:
    parts = ["PoC 在 GDB 下成功触发漏洞（路径A：确认触发）。"]
    if row.entry_function:
        parts.append(f"入口函数: {row.entry_function}.")
    if row.error:
        parts.append(str(row.error))
    return "".join(parts)[:8000]


def _build_reason_b(row: AppPocTask) -> str:
    parts = ["PoC 验证证伪/不可达（路径B：未触发漏洞）。"]
    if row.entry_function:
        parts.append(f"入口函数: {row.entry_function}.")
    if row.error:
        parts.append(str(row.error))
    return "".join(parts)[:8000]


def _build_reason_inconclusive(row: AppPocTask) -> str:
    parts = ["PoC 流程完成但未生成有效验证结论（Stage2 报告缺失，路径未判定）。"]
    if row.error:
        parts.append(str(row.error))
    return "".join(parts)[:8000]


# ────────────────────────── 引擎标识 ──────────────────────────


def _engine_name() -> str:
    return get_engine_config().name


def _engine_version() -> str:
    return get_engine_config().version


# ────────────────────────── 请求模型（宽松解析） ──────────────────────────


class _ContractSubject(BaseModel):
    model_config = ConfigDict(extra="allow")
    source_root: str = ""
    locator: str = ""
    name: str | None = None


class _RawReport(BaseModel):
    model_config = ConfigDict(extra="allow")
    markdown: str | None = None


class _Reporter(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str | None = None


class ContractRequest(BaseModel):
    """接口1请求体：复用 intake submission schema + 平台追加字段。

    仅解析引擎需要的最小集，未知字段忽略（契约 §4.1 / §9.2）。
    """

    model_config = ConfigDict(extra="allow")
    vuln_id: str = Field(..., min_length=1, max_length=128)
    project_id: str = Field(..., min_length=1)
    title: str | None = None
    subject: _ContractSubject | None = None
    raw_report: _RawReport | None = None
    reporter: _Reporter | None = None


class BatchRequest(BaseModel):
    """接口2请求体：{vuln_ids: [...]}（批量上限 100，契约 §4.2.2）。"""

    vuln_ids: list[str] = Field(min_length=1, max_length=1000)


class ConfirmedResultsRequest(BaseModel):
    """接口5请求体：按北京时间窗口查询已确认漏洞（契约 §4.3.2）。"""

    time_start: datetime
    time_end: datetime

    @model_validator(mode="after")
    def validate_window(self) -> "ConfirmedResultsRequest":
        if self.time_start.tzinfo is None or self.time_start.utcoffset() is None:
            raise ValueError("time_start must include timezone offset")
        if self.time_end.tzinfo is None or self.time_end.utcoffset() is None:
            raise ValueError("time_end must include timezone offset")
        if self.time_end <= self.time_start:
            raise ValueError("time_end must be greater than time_start")
        return self


# ────────────────────────── 响应构造（中文字面键精确匹配） ──────────────────────────


def contract_classification(
    row: AppPocTask, status: str, result: str | None
) -> dict[str, Any] | None:
    """构造 confirmed_category（仅接口2/4 元素；接口1响应不带此字段）。

    仅当 ``状态=已完成`` 且 ``结果=是``（路径A：GDB 触发崩溃）时，尝试填入
    配置的默认分类候选（如「内存安全类型」），并经接口6目录校验存在才返回；
    其余情况返回 None（契约 §6.2.6 C7）。
    """
    if status != CONTRACT_STATUS_DONE or result != "是":
        return None
    cfg = get_engine_config()
    if not cfg.emit_confirmed_category:
        return None
    candidate = (cfg.default_confirmed_category or "").strip()
    if not candidate:
        return None
    # 契约 §6.2.6：不得自行编造分类名；推送前必须经接口6目录校验。
    # 校验失败（目录不可用 / 候选不在目录）时安全降级为不填。
    try:
        from app.category_catalog import is_valid_category_name
        if not is_valid_category_name(candidate, engine=cfg):
            logger.warning(
                "confirmed_category candidate %r not in active catalog; omitting",
                candidate,
            )
            return None
    except Exception as exc:
        logger.warning("category catalog validation failed: %s; omitting confirmed_category", exc)
        return None
    return {"confirmed_category": candidate}


def _to_beijing_iso(dt: datetime) -> str:
    """格式化为北京时间 ISO8601（无微秒，+08:00 偏移）。"""
    if dt.tzinfo is None or dt.utcoffset() is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(BEIJING_TZ).replace(microsecond=0).isoformat()


def _beijing_naive_to_iso(dt: datetime) -> str:
    """把 naive 北京墙时间（本服务 now_local 约定）格式化为北京时间 ISO8601。

    finished_at / started_at 等列存的是 naive 北京墙时间（无 tzinfo），
    直接挂 +08:00 偏移输出，不再做时区转换。
    """
    return dt.replace(tzinfo=BEIJING_TZ, microsecond=dt.microsecond).replace(microsecond=0).isoformat()


def _to_beijing_naive(dt: datetime) -> datetime:
    """把任意 tz-aware 时间转成 naive 北京墙时间（用于与 finished_at 列比较）。"""
    if dt.tzinfo is None or dt.utcoffset() is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(BEIJING_TZ).replace(tzinfo=None)


def build_contract_response(
    vuln_id: str,
    status: str,
    result: str | None,
    reason: str | None,
    classification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """构造契约响应元素（接口1响应 / 接口2响应元素共用，§6）。

    手工构造 dict 以保证中文字面键严格匹配（契约 §6.1）。
    """
    payload: dict[str, Any] = {
        "漏洞ID": vuln_id,
        "推理引擎": {
            "引擎名称": _engine_name(),
            "引擎版本": _engine_version(),
        },
        "状态": status,
        "结果": result,
        "理由": reason,
    }
    if classification:
        payload.update(classification)
    return payload


# ────────────────────────── 入参 → 任务创建参数 ──────────────────────────


_FUNC_NAME_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)")


def _extract_entry_function(subject: _ContractSubject | None) -> str:
    """从 subject.locator 提取入口函数名；不可提取返回空串（Stage0 自行派生）。

    locator 形如 ``src/foo.c:bar:42``（file:function:line）→ 取函数段；
    纯函数名 ``bar`` → 直接取；纯文件路径 → 空串（让 Stage0 派生）。
    """
    if subject is None or not subject.locator:
        return ""
    parts = [p.strip() for p in subject.locator.split(":")]
    # 丢弃末尾的数字段（行号 / 列号）
    while len(parts) > 1 and parts[-1].isdigit():
        parts.pop()
    if not parts:
        return ""
    last = parts[-1]
    # 末段若像文件路径（含 / 或 .），不当作函数名
    if "/" in last or "." in last:
        return ""
    m = _FUNC_NAME_RE.match(last)
    return m.group(1) if m else ""


def _write_report_markdown(output_dir: str, markdown: str) -> str:
    """把 intake 的 raw_report.markdown 写成 poc CLI 的 -r 报告文件。

    返回报告文件绝对路径（<output_dir>/input/vuln_report.md）。
    """
    in_dir = Path(output_dir) / "input"
    in_dir.mkdir(parents=True, exist_ok=True)
    report_path = in_dir / "vuln_report.md"
    report_path.write_text(markdown, encoding="utf-8")
    return str(report_path)


# ────────────────────────── 路由 ──────────────────────────


def build_contract_router(prefix: str | None = None) -> APIRouter:
    """构建契约入站路由（接口1 + 接口2 + 接口5）。

    prefix 默认取 ``EngineConfig.endpoint_prefix``。
    """
    cfg = get_engine_config()
    router = APIRouter(prefix=prefix or cfg.endpoint_prefix, tags=["poc-gen-verify:contract"])

    @router.post("")
    def submit(req: ContractRequest) -> dict[str, Any]:
        """接口1：接收漏洞确认请求。

        同步响应统一返非终态「等待中」（契约 §4.1.2 永不返终态）。
        终态由 worker 完成后通过接口4主动推送，或平台接口2兜底拉取。
        """
        # 平台可能重试接口1（同 vuln_id）→ 幂等：已存在则返等待中，不重复创建。
        try:
            db_gen = get_db()
            db = next(db_gen)
            try:
                existing = (
                    db.query(AppPocTask)
                    .filter(
                        AppPocTask.vuln_id == req.vuln_id,
                        AppPocTask.is_deleted.is_(False),
                    )
                    .first()
                )
                if existing is not None:
                    logger.info("contract submit duplicate vuln_id=%s (idempotent)", req.vuln_id)
                    return build_contract_response(req.vuln_id, CONTRACT_STATUS_WAITING, None, None)

                # binary_dir = subject.source_root（漏洞/固件根目录），必填（契约 §4.1.1）
                if req.subject is None or not req.subject.source_root or not req.subject.source_root.strip():
                    raise HTTPException(status_code=422, detail="subject.source_root is required (binary_dir)")
                binary_dir = req.subject.source_root.strip()

                # 报告：优先 raw_report.markdown；缺失时用 title 合成最小 markdown
                # （契约 §4.1.1 raw_report 可选，避免合法 intake 被 422 拒绝）
                markdown = req.raw_report.markdown if req.raw_report else None
                if not markdown:
                    markdown = f"# {req.title or req.vuln_id}\n"

                entry_function = _extract_entry_function(req.subject)
                created_by = (req.reporter.name if req.reporter else None) or "vuln-confirm-engine"

                from app.service.task_service import get_task_service
                rec = get_task_service().create_contract_task(
                    db,
                    project_id=req.project_id,
                    vuln_id=req.vuln_id,
                    task_name=req.title or req.vuln_id,
                    entry_function=entry_function,
                    binary_dir=binary_dir,
                    report_markdown=markdown,
                    created_by=created_by,
                )
            finally:
                try:
                    next(db_gen)
                except StopIteration:
                    pass
        except HTTPException:
            raise  # 422 等业务校验错误透传（不重试，契约 §4.1.3）
        except IntegrityError:
            logger.info("contract submit duplicate vuln_id=%s (IntegrityError idempotent)", req.vuln_id)
        except ValueError as exc:
            # 业务校验错误 → 4xx（契约 §4.1.3 不重试）
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception:
            logger.exception("contract submit failed vuln_id=%s", req.vuln_id)
            raise HTTPException(status_code=500, detail="engine internal error") from None
        return build_contract_response(req.vuln_id, CONTRACT_STATUS_WAITING, None, None)

    @router.post("/results/batch")
    def results_batch(req: BatchRequest) -> dict[str, Any]:
        """接口2：批量拉取结果（兜底，平台每 60s 调用）。

        按 vuln_id 查询当前状态 + poc_path，映射为契约 schema。
        未找到的 vuln_id 省略（契约 §4.2.3 平台下次 polling 再拉）。
        """
        db_gen = get_db()
        db = next(db_gen)
        try:
            tasks = (
                db.execute(
                    select(AppPocTask).where(
                        AppPocTask.vuln_id.in_(req.vuln_ids),
                        AppPocTask.is_deleted.is_(False),
                    )
                )
                .scalars()
                .all()
            )
            by_vuln: dict[str, AppPocTask] = {t.vuln_id: t for t in tasks if t.vuln_id}
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass

        results: list[dict[str, Any]] = []
        for vid in req.vuln_ids:
            row = by_vuln.get(vid)
            if row is None:
                continue  # 未知 vuln_id：省略，平台下次 polling 再拉
            status, result, reason = map_contract_outcome(row)
            classification = contract_classification(row, status, result)
            results.append(build_contract_response(vid, status, result, reason, classification))
        return {"results": results}

    @router.post("/results/confirmed")
    def results_confirmed(req: ConfirmedResultsRequest) -> dict[str, Any]:
        """接口5：按时间窗口查询已确认漏洞清单（对账 / 审计用）。

        请求时间允许任意 timezone offset；查询前统一转换为 UTC 比较，
        响应「处理时间」统一输出为北京时间 ``+08:00``。
        只返回 ``status=succeeded`` 且 ``poc_path=a``（结果=是）的任务；
        ``finished_at`` 作为契约「处理时间」，窗口两端均包含。
        """
        start = _to_beijing_naive(req.time_start)
        end = _to_beijing_naive(req.time_end)
        db_gen = get_db()
        db = next(db_gen)
        try:
            rows = (
                db.execute(
                    select(AppPocTask.vuln_id, AppPocTask.finished_at, AppPocTask.stages_json)
                    .where(
                        AppPocTask.is_deleted.is_(False),
                        AppPocTask.status == "succeeded",
                        AppPocTask.vuln_id.is_not(None),
                        AppPocTask.finished_at.is_not(None),
                        AppPocTask.finished_at >= start,
                        AppPocTask.finished_at <= end,
                    )
                    .order_by(AppPocTask.finished_at.asc(), AppPocTask.vuln_id.asc())
                )
                .all()
            )
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass

        # 仅保留 poc_path=a（结果=是）。poc_path 存于 stages_json；内存过滤。
        # 同一 vuln_id 去重，保留窗口内最新处理时间。
        by_vuln_id: dict[str, datetime] = {}
        for row in rows:
            vuln_id, finished_at, stages_json = row
            if vuln_id is None or finished_at is None:
                continue
            if not isinstance(stages_json, dict) or stages_json.get("poc_path") != "a":
                continue
            # finished_at 为 naive 北京墙时间，直接比较
            if vuln_id not in by_vuln_id or finished_at > by_vuln_id[vuln_id]:
                by_vuln_id[vuln_id] = finished_at

        return {
            "results": [
                {"漏洞ID": vuln_id, "处理时间": _beijing_naive_to_iso(processed_at)}
                for vuln_id, processed_at in sorted(
                    by_vuln_id.items(), key=lambda item: (item[1], item[0])
                )
            ]
        }

    return router
