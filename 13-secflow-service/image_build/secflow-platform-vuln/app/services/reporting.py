from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from app.config import get_config
from app.models.database import ActionExecution, Case, ManualTask, Result
from app.services.lifecycle_engine import build_case_fileserver_root, get_lifecycle_state


REPORT_INDEX_KEY = "report_registry"
CURRENT_REPORT_KEY = "current_report_id"
DOCUMENTS_KEY = "documents"
REPORT_TIME_FMT = "%Y-%m-%d %H:%M:%S UTC"
RAW_REPORT_KEY = "raw_report"


def _now_iso() -> str:
    return datetime.utcnow().isoformat()


def _slugify(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", (value or "").strip())
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return text or "report"


def _safe_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def _display_meta(case: Case) -> dict[str, Any]:
    try:
        return json.loads(case.display_meta_json or "{}")
    except Exception:
        return {}


def _save_display_meta(case: Case, display_meta: dict[str, Any]) -> None:
    case.display_meta_json = json.dumps(display_meta, ensure_ascii=False)


def _source_meta(case: Case) -> dict[str, Any]:
    try:
        return json.loads(case.source_meta_json or "{}")
    except Exception:
        return {}


def _target_meta(case: Case) -> dict[str, Any]:
    try:
        return json.loads(case.target_meta_json or "{}")
    except Exception:
        return {}


def _case_reports_root(case_id: str) -> Path:
    base_path = Path(get_config().storage.base_path).resolve()
    return base_path / "cases" / case_id / "reports"


def _report_download_url(case_id: str, report_id: str) -> str:
    return f"/api/vuln/cases/{case_id}/report?report_id={report_id}&download=1"


def _fileserver_report_path(case_id: str, relative_path: str) -> str:
    root = build_case_fileserver_root(case_id).get("root_path") or ""
    return f"{root}/reports/{relative_path}".replace("//", "/")


def _load_registry(case: Case) -> dict[str, Any]:
    display_meta = _display_meta(case)
    registry = display_meta.get(REPORT_INDEX_KEY)
    if not isinstance(registry, dict):
        return {CURRENT_REPORT_KEY: None, DOCUMENTS_KEY: []}
    documents = registry.get(DOCUMENTS_KEY)
    if not isinstance(documents, list):
        documents = []
    current_report_id = registry.get(CURRENT_REPORT_KEY)
    return {
        CURRENT_REPORT_KEY: current_report_id if isinstance(current_report_id, str) and current_report_id else None,
        DOCUMENTS_KEY: [dict(item) for item in documents if isinstance(item, dict)],
    }


def _save_registry(case: Case, registry: dict[str, Any]) -> None:
    display_meta = _display_meta(case)
    display_meta[REPORT_INDEX_KEY] = {
        CURRENT_REPORT_KEY: registry.get(CURRENT_REPORT_KEY),
        DOCUMENTS_KEY: registry.get(DOCUMENTS_KEY, []),
    }
    case.display_meta_json = json.dumps(display_meta, ensure_ascii=False)


def list_case_reports(case: Case) -> list[dict[str, Any]]:
    registry = _load_registry(case)
    items = registry.get(DOCUMENTS_KEY, [])
    return sorted(
        items,
        key=lambda item: (
            str(item.get("generated_at") or ""),
            str(item.get("report_id") or ""),
        ),
        reverse=True,
    )


def get_current_report_summary(case: Case) -> dict[str, Any] | None:
    raw_report = ensure_case_raw_report(case)
    registry = _load_registry(case)
    current_report_id = registry.get(CURRENT_REPORT_KEY)
    items = registry.get(DOCUMENTS_KEY, [])
    raw_report_id = raw_report.get("report_id") if raw_report else None
    if raw_report_id:
        for item in items:
            if item.get("report_id") == raw_report_id:
                return item
    if current_report_id:
        for item in items:
            if item.get("report_id") == current_report_id:
                return item
    return items[0] if items else None


def _excerpt(markdown: str, limit: int = 220) -> str:
    plain = re.sub(r"[#>*_`~\[\]\(\)-]", " ", markdown or "")
    plain = re.sub(r"\s+", " ", plain).strip()
    return plain[:limit]


def _normalize_raw_report(raw_report: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(raw_report, dict):
        return None
    markdown = str(raw_report.get("markdown") or "").strip()
    if not markdown:
        return None
    return {
        "title": str(raw_report.get("title") or "原始漏洞报告").strip() or "原始漏洞报告",
        "markdown": markdown,
        "report_id": str(raw_report.get("report_id") or "raw-intake").strip() or "raw-intake",
        "source": str(raw_report.get("source") or "").strip() or None,
        "reported_at": raw_report.get("reported_at"),
        "ingest_source": str(raw_report.get("ingest_source") or "").strip() or "field",
    }


def _extract_raw_report_from_artifact(artifact: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(artifact, dict) or artifact.get("kind") != "report":
        return None
    metadata = artifact.get("metadata") if isinstance(artifact.get("metadata"), dict) else {}
    markdown = str(
        artifact.get("content")
        or metadata.get("markdown")
        or metadata.get("content")
        or ""
    ).strip()
    if not markdown:
        return None
    return {
        "title": str(artifact.get("name") or metadata.get("title") or "原始漏洞报告").strip() or "原始漏洞报告",
        "markdown": markdown,
        "report_id": str(artifact.get("artifact_id") or metadata.get("report_id") or "raw-intake").strip() or "raw-intake",
        "source": str(metadata.get("source") or artifact.get("content_ref") or "artifact").strip() or "artifact",
        "reported_at": metadata.get("reported_at"),
        "ingest_source": "artifact",
    }


def resolve_raw_report(display_meta: dict[str, Any]) -> dict[str, Any] | None:
    normalized = _normalize_raw_report(display_meta.get(RAW_REPORT_KEY))
    if normalized:
        return normalized
    artifacts = display_meta.get("artifacts")
    if isinstance(artifacts, list):
        for artifact in artifacts:
            extracted = _extract_raw_report_from_artifact(artifact)
            if extracted:
                return extracted
    return None


def ensure_case_raw_report(case: Case) -> dict[str, Any] | None:
    display_meta = _display_meta(case)
    normalized = resolve_raw_report(display_meta)
    current = _normalize_raw_report(display_meta.get(RAW_REPORT_KEY))
    if normalized != current:
        display_meta[RAW_REPORT_KEY] = normalized
        _save_display_meta(case, display_meta)
    return normalized


def read_report_content(storage_path: str | None) -> str | None:
    if not storage_path:
        return None
    path = Path(storage_path)
    if not path.exists() or not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _extract_markdown_candidates(payload: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    keys = [
        "report_markdown",
        "markdown",
        "content_markdown",
        "final_report_markdown",
        "module_report_markdown",
        "report",
        "content",
        "text",
        "message",
    ]
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            candidates.append(value.strip())
        elif isinstance(value, dict):
            for nested_key in ("markdown", "content", "text", "body"):
                nested = value.get(nested_key)
                if isinstance(nested, str) and nested.strip():
                    candidates.append(nested.strip())
    return candidates


def build_intake_report_markdown(case: Case) -> str:
    source_meta = _source_meta(case)
    target_meta = _target_meta(case)
    display_meta = _display_meta(case)
    evidence = display_meta.get("evidence") or {}
    artifacts = display_meta.get("artifacts") or []
    reporter = source_meta.get("reporter") or {}
    lines = [
        f"# {case.title}",
        "",
        f"- 严重度: `{case.severity}`",
        f"- 置信度: `{case.confidence}`",
        f"- 当前阶段: `{case.current_stage}`",
        f"- 报告 ID: `{source_meta.get('report_id') or case.id}`",
        f"- 上报时间: `{source_meta.get('reported_at') or case.created_at.strftime(REPORT_TIME_FMT)}`",
        f"- 上报方: `{reporter.get('name') or case.created_by or 'unknown'}`",
        "",
        "## 摘要",
        "",
        case.summary or evidence.get("summary") or "暂无摘要",
        "",
        "## 目标对象",
        "",
        f"- 类型: `{target_meta.get('type') or 'unknown'}`",
        f"- 定位: `{target_meta.get('locator') or 'unknown'}`",
    ]
    if target_meta.get("name"):
        lines.append(f"- 名称: `{target_meta.get('name')}`")
    reproduction_hint = evidence.get("reproduction_hint")
    if reproduction_hint:
        lines.extend(["", "## 复现提示", "", str(reproduction_hint)])
    references = evidence.get("references") if isinstance(evidence.get("references"), list) else []
    if references:
        lines.extend(["", "## 参考信息", ""])
        for item in references:
            if isinstance(item, dict):
                label = item.get("title") or item.get("name") or item.get("url") or "reference"
                value = item.get("url") or item.get("path") or item.get("value") or ""
                lines.append(f"- {label}: {value}".rstrip(": "))
            else:
                lines.append(f"- {item}")
    if artifacts:
        lines.extend(["", "## 上报产物", ""])
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            lines.append(
                f"- `{artifact.get('kind') or 'other'}` {artifact.get('name') or artifact.get('path') or 'unnamed'}"
            )
    return "\n".join(lines).strip() + "\n"


def build_result_report_markdown(
    case: Case,
    result: Result,
    *,
    action: ActionExecution | None = None,
) -> str:
    result_meta = json.loads(result.result_meta_json or "{}")
    raw_payload = json.loads(result.raw_payload_json or "{}")
    markdown_candidates = _extract_markdown_candidates(raw_payload) + _extract_markdown_candidates(result_meta)
    if markdown_candidates:
        return markdown_candidates[0].strip() + ("\n" if not markdown_candidates[0].endswith("\n") else "")

    lines = [
        f"# {case.title} - {result.result_type} 报告",
        "",
        f"- 结果类型: `{result.result_type}`",
        f"- 结果状态: `{result.status}`",
        f"- 置信度: `{result.confidence}`",
        f"- 来源服务: `{result.source_service_id or (action.target_service_id if action else 'unknown')}`",
        f"- 生成时间: `{result.created_at.strftime(REPORT_TIME_FMT)}`",
    ]
    if action:
        lines.append(f"- 所属阶段: `{action.stage}`")
        lines.append(f"- 动作类型: `{action.action_type}`")
    if result.summary:
        lines.extend(["", "## 结果摘要", "", result.summary])
    if result.suggested_stage or result.suggested_decision:
        lines.extend(["", "## 引擎建议", ""])
        if result.suggested_stage:
            lines.append(f"- 建议阶段: `{result.suggested_stage}`")
        if result.suggested_decision:
            lines.append(f"- 建议结论: `{result.suggested_decision}`")
    if result_meta:
        lines.extend(["", "## 结构化结果", "", "```json", _safe_json(result_meta), "```"])
    if raw_payload:
        lines.extend(["", "## 原始回传", "", "```json", _safe_json(raw_payload), "```"])
    return "\n".join(lines).strip() + "\n"


def build_final_report_markdown(
    case: Case,
    *,
    results: list[Result],
    actions: list[ActionExecution],
    manual_tasks: list[ManualTask],
) -> str:
    lifecycle = get_lifecycle_state(case)
    lines = [
        f"# {case.title} - 最终报告",
        "",
        f"- 严重度: `{case.severity}`",
        f"- 当前阶段: `{case.current_stage}`",
        f"- 当前状态: `{case.current_status}`",
        f"- 结论: `{case.decision_status}`",
        f"- 验证结果: `{lifecycle.get('validation_result') or 'unknown'}`",
        f"- 结束原因: `{lifecycle.get('finished_reason') or 'unknown'}`",
        f"- 更新时间: `{case.updated_at.strftime(REPORT_TIME_FMT)}`",
        "",
        "## 总结",
        "",
        case.summary or "暂无总结",
    ]
    if results:
        lines.extend(["", "## 关键结果", ""])
        for result in results[:6]:
            lines.append(
                f"- `{result.result_type}` / `{result.status}` / 置信度 `{result.confidence}`: {result.summary or '暂无摘要'}"
            )
    if actions:
        lines.extend(["", "## 动作执行概览", ""])
        for action in actions[:6]:
            lines.append(
                f"- `{action.action_type}` / `{action.execution_status}` / `{action.target_service_id or 'unknown'}`: {action.result_summary or '暂无结果摘要'}"
            )
    open_tasks = [task for task in manual_tasks if task.status not in {"completed", "closed"}]
    if manual_tasks:
        lines.extend(["", "## 人工任务", ""])
        lines.append(f"- 总数: `{len(manual_tasks)}`")
        lines.append(f"- 未关闭: `{len(open_tasks)}`")
    return "\n".join(lines).strip() + "\n"


def write_case_report_document(
    case: Case,
    *,
    report_id: str,
    title: str,
    report_kind: str,
    render_format: str,
    stage: str,
    markdown: str,
    generated_by: str,
    generated_at: str | None = None,
    source_service_id: str | None = None,
    result_id: str | None = None,
    set_as_current: bool = False,
) -> dict[str, Any]:
    timestamp = generated_at or _now_iso()
    report_root = _case_reports_root(case.id)
    relative_path = Path(_slugify(stage)) / f"{_slugify(report_id)}.md"
    storage_path = report_root / relative_path
    storage_path.parent.mkdir(parents=True, exist_ok=True)
    storage_path.write_text(markdown, encoding="utf-8")

    doc = {
        "report_id": report_id,
        "title": title,
        "report_kind": report_kind,
        "render_format": render_format,
        "stage": stage,
        "storage_path": str(storage_path),
        "fileserver_path": _fileserver_report_path(case.id, relative_path.as_posix()),
        "download_url": _report_download_url(case.id, report_id),
        "excerpt": _excerpt(markdown),
        "generated_by": generated_by,
        "generated_at": timestamp,
        "source_service_id": source_service_id,
        "result_id": result_id,
    }
    registry = _load_registry(case)
    docs = [item for item in registry.get(DOCUMENTS_KEY, []) if item.get("report_id") != report_id]
    docs.append(doc)
    docs = sorted(docs, key=lambda item: (str(item.get("generated_at") or ""), str(item.get("report_id") or "")), reverse=True)
    registry[DOCUMENTS_KEY] = docs
    if set_as_current or not registry.get(CURRENT_REPORT_KEY):
        registry[CURRENT_REPORT_KEY] = report_id
    _save_registry(case, registry)
    return doc


def ensure_case_report_documents(
    case: Case,
    *,
    actions: list[ActionExecution],
    results: list[Result],
    manual_tasks: list[ManualTask],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    raw_report = ensure_case_raw_report(case)
    existing_docs = {item.get("report_id"): item for item in list_case_reports(case)}
    if raw_report:
        raw_report_id = raw_report.get("report_id") or "raw-intake"
        write_case_report_document(
            case,
            report_id=raw_report_id,
            title=raw_report.get("title") or "原始漏洞报告",
            report_kind="imported_raw",
            render_format="markdown",
            stage="intake",
            markdown=raw_report.get("markdown") or "",
            generated_by=raw_report.get("source") or "vuln-intake",
            generated_at=str(raw_report.get("reported_at") or case.created_at.isoformat()),
            source_service_id=raw_report.get("source"),
            set_as_current=True,
        )
        existing_docs = {item.get("report_id"): item for item in list_case_reports(case)}
    if "intake" not in existing_docs:
        write_case_report_document(
            case,
            report_id="intake",
            title="原始上报报告",
            report_kind="imported",
            render_format="markdown",
            stage="intake",
            markdown=build_intake_report_markdown(case),
            generated_by="vuln-engine",
            generated_at=case.created_at.isoformat(),
            set_as_current=not bool(existing_docs),
        )
    actions_by_id = {item.id: item for item in actions}
    for result in results:
        report_id = f"result-{result.id}"
        if report_id in existing_docs:
            continue
        action = actions_by_id.get(result.action_execution_id)
        write_case_report_document(
            case,
            report_id=report_id,
            title=f"{result.result_type} 报告",
            report_kind="verification" if (action and action.stage == "validation") else "analysis",
            render_format="markdown",
            stage=action.stage if action else case.current_stage,
            markdown=build_result_report_markdown(case, result, action=action),
            generated_by=result.source_service_id or (action.target_service_id if action else "vuln-engine"),
            generated_at=result.created_at.isoformat(),
            source_service_id=result.source_service_id,
            result_id=result.id,
            set_as_current=True,
        )
    if case.current_stage == "finished":
        write_case_report_document(
            case,
            report_id="final",
            title="最终汇总报告",
            report_kind="final",
            render_format="markdown",
            stage="final",
            markdown=build_final_report_markdown(case, results=results, actions=actions, manual_tasks=manual_tasks),
            generated_by="vuln-engine",
            generated_at=case.updated_at.isoformat(),
            set_as_current=True,
        )
    docs = list_case_reports(case)
    current = get_current_report_summary(case)
    return docs, current


def build_display_summary(case_payload: dict[str, Any], current_report: dict[str, Any] | None) -> dict[str, Any]:
    reporter = case_payload.get("reporter") or {}
    subject = case_payload.get("subject") or {}
    source_task = case_payload.get("source_task") or {}
    key_points = [
        f"当前阶段：{case_payload.get('current_stage') or '-'}",
        f"当前结论：{case_payload.get('decision_status') or '-'}",
        f"验证结果：{case_payload.get('validation_result') or '-'}",
    ]
    if case_payload.get("finished_reason"):
        key_points.append(f"结束原因：{case_payload.get('finished_reason')}")
    if current_report and current_report.get("excerpt"):
        key_points.append(str(current_report.get("excerpt")))
    return {
        "title": case_payload.get("title"),
        "subtitle": case_payload.get("summary") or case_payload.get("category") or "漏洞案例",
        "severity": case_payload.get("severity"),
        "confidence": case_payload.get("confidence"),
        "current_stage": case_payload.get("current_stage"),
        "decision_status": case_payload.get("decision_status"),
        "validation_result": case_payload.get("validation_result"),
        "finished_reason": case_payload.get("finished_reason"),
        "reporter": reporter,
        "subject": subject,
        "source_task": source_task,
        "source_report_ids": case_payload.get("source_report_ids") or [],
        "reported_at": case_payload.get("reported_at"),
        "key_points": key_points[:8],
        "current_report_id": current_report.get("report_id") if current_report else None,
        "current_report_title": current_report.get("title") if current_report else None,
        "current_report_updated_at": current_report.get("generated_at") if current_report else None,
    }


def build_evidence_summary(case_payload: dict[str, Any], results_payload: list[dict[str, Any]]) -> dict[str, Any]:
    evidence = case_payload.get("evidence") or {}
    artifacts = case_payload.get("artifacts") or []
    proof_items: list[dict[str, Any]] = []
    for item in results_payload[:8]:
        proof_items.append({
            "result_id": item.get("id"),
            "result_type": item.get("result_type"),
            "status": item.get("status"),
            "summary": item.get("summary"),
            "confidence": item.get("confidence"),
            "source_service_id": item.get("source_service_id"),
        })
    return {
        "summary": evidence.get("summary") or case_payload.get("summary"),
        "reproduction_hint": evidence.get("reproduction_hint"),
        "references": evidence.get("references") or [],
        "artifacts": artifacts,
        "proof_items": proof_items,
    }


def build_result_summary(
    results_payload: list[dict[str, Any]],
    docs: list[dict[str, Any]],
    case_payload: dict[str, Any],
) -> dict[str, Any]:
    latest_results = results_payload[:5]
    verification_outcome = case_payload.get("validation_result")
    decision_candidates = [
        {
            "result_id": item.get("id"),
            "suggested_decision": item.get("suggested_decision"),
            "summary": item.get("summary"),
        }
        for item in results_payload
        if item.get("suggested_decision")
    ][:5]
    return {
        "latest_results": latest_results,
        "report_candidates": docs,
        "verification_outcome": verification_outcome,
        "decision_candidates": decision_candidates,
    }


def build_workspace_summary(
    case_payload: dict[str, Any],
    *,
    timeline_count: int,
    action_count: int,
    manual_task_count: int,
    result_count: int,
) -> dict[str, Any]:
    source_task = case_payload.get("source_task") or {}
    refs = []
    for key in ("service_name", "task_id", "execution_id", "run_id", "parent_task_id", "parent_stage_name"):
        value = source_task.get(key)
        if value:
            refs.append({"key": key, "value": value})
    return {
        "timeline_count": timeline_count,
        "action_count": action_count,
        "manual_task_count": manual_task_count,
        "result_count": result_count,
        "related_execution_refs": refs,
        "files_root_path": case_payload.get("files_root_path"),
    }
