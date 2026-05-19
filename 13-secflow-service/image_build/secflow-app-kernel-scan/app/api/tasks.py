from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from app.core.config import get_config
from app.db.database import get_database
from app.services.event_service import get_event_service
from app.services.task_service import get_task_service

router = APIRouter()


# ─── Request / Response Models ───────────────────────────────────────────────


class TaskCreateRequest(BaseModel):
    """创建内核扫描任务的请求体"""

    title: str = Field(..., description="任务标题，用于前端展示", examples=["drivers/gpu ioctl 入口扫描"])
    pipeline_mode: Literal["entry_only", "audit_only", "poc_only", "entry_audit_poc"] = Field(
        "entry_audit_poc",
        description=(
            "流水线模式：\n"
            "- `entry_only`: 仅扫描攻击入口\n"
            "- `audit_only`: 仅漏洞审计（需提供 entrylist 文件路径）\n"
            "- `poc_only`: 仅 PoC 验证（需提供 kernel_dir、report_dir；ADB server 从 ~/.bashrc 读取）\n"
            "- `entry_audit_poc`: 完整三阶段流水线"
        ),
    )
    kernel_dir: str | None = Field(
        None,
        description="内核源码目录路径（容器内路径）。`poc_only` 模式必填；其它模式为空则使用默认 /workspace/kernel",
        examples=["/workspace/kernel"],
    )
    report_dir: str | None = Field(
        None,
        description=(
            "漏洞报告目录或单个 Markdown 报告文件路径（容器内路径）。"
            "`poc_only` 模式必填；`entry_audit_poc` 模式为空时默认使用本任务 audit stage 输出目录。"
        ),
        examples=["/workspace/audit/kscan-task-xxxxxxxx"],
    )
    device_ip: str | None = Field(
        None,
        description=(
            "兼容旧字段。PoC stage 不再要求前端传该字段；`/devices/adb/connect` 固定连接 "
            "`172.31.30.81:15037`，并由 `~/.bashrc` 中的 `ADB_SERVER_SOCKET` 提供给 PoC。"
        ),
        examples=[None],
    )
    entrylist: str | None = Field(
        None,
        description=(
            "攻击入口清单文件路径（容器内绝对路径）。内容为脚本 `ask_claude_kernaudit_v2.py` 期望的文本格式："
            "每行一条 `<func> <method>`，例如 `gpu_ioctl ioctl`。entry stage 产物 "
            "`{workspace_root}/entry/{task_id}/entry_scan_results.txt`（格式 `func [method]`）可直接作为此字段的输入。\n"
            "- `audit_only` 模式必填；\n"
            "- `entry_audit_poc` 模式下可选：若提供，audit stage 直接使用该文件；否则回退到 entry stage 输出的 `entry_scan_results.json`"
        ),
        examples=["/workspace/entry/kscan-task-xxxxxxxx/entry_scan_results.txt"],
    )
    notes: str | None = Field(None, description="备注信息")
    entry_threads: int | None = Field(
        None,
        ge=1,
        le=32,
        description="entry 阶段并行线程数，为空则使用服务默认值（4）",
    )
    audit_threads: int | None = Field(
        None,
        ge=1,
        le=32,
        description="audit 阶段并行线程数，为空则使用服务默认值（4）",
    )
    poc_threads: int | None = Field(
        None,
        ge=1,
        le=16,
        description="poc 阶段并行线程数，为空则使用服务默认值（2）",
    )


class TaskCreateResponse(BaseModel):
    """创建任务的响应"""

    task_id: str = Field(..., description="任务唯一 ID")
    attempt_id: str = Field(..., description="本次执行尝试 ID")
    status: str = Field(..., description="任务状态", examples=["queued"])


class StageRunResponse(BaseModel):
    """阶段执行状态"""

    stage_run_id: str
    attempt_id: str
    stage_name: Literal["entry", "audit", "poc"] = Field(..., description="阶段名称")
    status: str = Field(..., description="阶段状态: pending/running/succeeded/failed/skipped/cancelled/timed_out")
    return_code: int | None = None
    started_at: str | None = None
    finished_at: str | None = None
    message: str | None = None
    metadata_json: str = "{}"


class TaskDetailResponse(BaseModel):
    """任务详情响应"""

    task_id: str
    title: str
    pipeline_mode: str = Field(..., description="流水线模式")
    kernel_dir: str = Field(..., description="内核源码目录")
    status: str = Field(..., description="任务状态: queued/running/succeeded/partial_success/failed/cancel_requested/cancelled")
    current_stage: str | None = Field(None, description="当前正在执行的阶段")
    latest_attempt_id: str | None = None
    attempt_count: int = 0
    notes: str | None = None
    created_by: str = ""
    created_at: str = ""
    updated_at: str = ""
    started_at: str | None = None
    finished_at: str | None = None
    message: str | None = None
    stage_runs: list[StageRunResponse] = Field(default_factory=list, description="各阶段执行状态")


class TaskSummaryResponse(BaseModel):
    """任务摘要（列表用）"""

    task_id: str
    title: str
    pipeline_mode: str
    kernel_dir: str
    status: str
    current_stage: str | None = None
    created_at: str = ""
    started_at: str | None = None
    finished_at: str | None = None
    message: str | None = None


class PagedTaskResponse(BaseModel):
    """分页任务列表响应"""

    items: list[TaskSummaryResponse]
    total: int = Field(..., description="总任务数")
    page: int
    per_page: int


class CancelResponse(BaseModel):
    """取消任务响应"""

    task_id: str
    status: str = Field(..., description="取消后的状态", examples=["cancel_requested"])


class DeleteResponse(BaseModel):
    """删除任务响应"""

    task_id: str
    status: str = Field(..., description="删除后的状态", examples=["deleted"])


class EventResponse(BaseModel):
    """事件条目"""

    event_seq: int = Field(..., description="事件序号，用于分页游标")
    event_id: str
    task_id: str
    attempt_id: str | None = None
    stage_name: str | None = None
    event_type: str = Field(..., description="事件类型: stage.started/stage.completed/task.completed/task.failed/task.cancelled")
    level: str = Field(..., description="日志级别: debug/info/warning/error")
    message: str
    payload_json: str = "{}"
    created_at: str


class EventPageResponse(BaseModel):
    """分页事件列表响应"""

    items: list[EventResponse]
    next_cursor: int | None = Field(None, description="下一页游标，传入 after_seq 参数实现翻页；为 null 表示无更多数据")


class EntryResultResponse(BaseModel):
    """Entry 阶段文本结果"""

    task_id: str
    path: str = Field(..., description="容器内文件绝对路径")
    exists: bool
    size: int = Field(0, description="文件字节数，不存在时为 0")
    content: str = Field("", description="文件文本内容（UTF-8 解码）")


# ─── API Endpoints ───────────────────────────────────────────────────────────


@router.post(
    "/tasks",
    response_model=TaskCreateResponse,
    summary="创建扫描任务",
    description=(
        "创建一个内核安全扫描任务。任务创建后自动进入队列，由后台调度器拉取执行。\n\n"
        "**流水线模式说明：**\n"
        "- `entry_audit_poc`（默认）: 完整流水线，先扫描攻击入口，再审计漏洞，最后 PoC 验证\n"
        "- `entry_only`: 仅扫描内核源码中的用户态可达攻击入口\n"
        "- `audit_only`: 仅对指定入口进行漏洞审计（需通过 `entrylist` 字段提供入口清单文件路径）\n"
        "- `poc_only`: 仅对已有审计报告中的漏洞进行 PoC 验证（需提供 `kernel_dir`、`report_dir`；ADB server 从 `~/.bashrc` 读取）"
    ),
)
def create_task(req: TaskCreateRequest):
    if req.pipeline_mode == "poc_only" and not (req.kernel_dir or "").strip():
        raise HTTPException(422, "kernel_dir is required for poc_only tasks")
    if req.pipeline_mode == "poc_only" and not (req.report_dir or "").strip():
        raise HTTPException(422, "report_dir is required for poc_only tasks")

    result = get_task_service().create_task(
        title=req.title,
        pipeline_mode=req.pipeline_mode,
        kernel_dir=req.kernel_dir,
        report_dir=req.report_dir,
        device_ip=req.device_ip,
        entrylist=req.entrylist,
        notes=req.notes,
        entry_threads=req.entry_threads,
        audit_threads=req.audit_threads,
        poc_threads=req.poc_threads,
    )
    return TaskCreateResponse(**result)


@router.get(
    "/tasks",
    response_model=PagedTaskResponse,
    summary="获取任务列表",
    description="分页获取所有扫描任务，按创建时间倒序排列。",
)
def list_tasks(
    page: int = Query(1, ge=1, description="页码，从 1 开始"),
    per_page: int = Query(20, ge=1, le=100, description="每页条数，最大 100"),
):
    items, total = get_task_service().list_tasks(page=page, per_page=per_page)
    return {"items": items, "total": total, "page": page, "per_page": per_page}


@router.get(
    "/tasks/{task_id}",
    response_model=TaskDetailResponse,
    summary="获取任务详情",
    description="获取单个任务的完整信息，包括各阶段执行状态。",
)
def get_task(task_id: str):
    task = get_task_service().get_task(task_id)
    if not task:
        raise HTTPException(404, "task not found")
    with get_database().connect() as conn:
        stages = conn.execute(
            "select * from kernel_scan_stage_runs where attempt_id = ? order by stage_name",
            (task.get("latest_attempt_id"),),
        ).fetchall()
    task["stage_runs"] = [dict(s) for s in stages] if stages else []
    return task


@router.post(
    "/tasks/{task_id}/cancel",
    response_model=CancelResponse,
    summary="取消任务",
    description="请求取消一个正在排队或运行中的任务。已完成/已取消的任务无法再取消。",
)
def cancel_task(task_id: str):
    success = get_task_service().cancel_task(task_id)
    if not success:
        raise HTTPException(400, "task cannot be cancelled (already finished or not found)")
    return {"task_id": task_id, "status": "cancel_requested"}


@router.delete(
    "/tasks/{task_id}",
    response_model=DeleteResponse,
    summary="删除任务",
    description=(
        "删除任务及其所有 attempts / 阶段记录 / 事件 / 产物。仅当任务处于终态"
        "（`succeeded` / `partial_success` / `failed` / `cancelled`）时可删除；"
        "若仍在 `queued` / `running` / `cancel_requested` 状态，请先调用取消接口等待任务终止。"
    ),
)
def delete_task(task_id: str):
    outcome = get_task_service().delete_task(task_id)
    if outcome == "not_found":
        raise HTTPException(404, "task not found")
    if outcome == "busy":
        raise HTTPException(
            409,
            "task is not in a terminal state; cancel it and wait for it to finish before deleting",
        )
    return {"task_id": task_id, "status": "deleted"}


@router.get(
    "/tasks/{task_id}/events",
    response_model=EventPageResponse,
    summary="获取任务事件流",
    description=(
        "获取任务的事件日志，支持游标分页。前端可轮询此接口实现实时状态更新。\n\n"
        "**使用方式：**\n"
        "1. 首次请求不传 `after_seq`（默认 0）\n"
        "2. 响应中 `next_cursor` 非 null 时，下次请求传入 `after_seq=next_cursor`\n"
        "3. `next_cursor` 为 null 表示暂无更多事件，稍后重试"
    ),
)
def get_events(
    task_id: str,
    after_seq: int = Query(0, ge=0, description="游标：只返回 event_seq > after_seq 的事件"),
    limit: int = Query(100, ge=1, le=500, description="单次最多返回条数"),
):
    task = get_task_service().get_task(task_id)
    if not task:
        raise HTTPException(404, "task not found")
    events = get_event_service().list_events(task_id, after_seq=after_seq, limit=limit)
    next_cursor = events[-1]["event_seq"] if events else None
    return {"items": events, "next_cursor": next_cursor}


def _entry_txt_path(task_id: str) -> Path:
    workspace_root = Path(get_config().workspace_root)
    return workspace_root / "entry" / task_id / "entry_scan_results.txt"


@router.get(
    "/tasks/{task_id}/entry/result",
    response_model=EntryResultResponse,
    summary="获取 entry 阶段文本结果",
    description=(
        "返回 `{workspace_root}/entry/{task_id}/entry_scan_results.txt` 的文本内容（JSON 包裹）。"
        "若需直接下载纯文本，使用 `?format=text` 参数。"
    ),
)
def get_entry_result(
    task_id: str,
    format: Literal["json", "text"] = Query("json", description="返回格式：json 或 text"),
):
    task = get_task_service().get_task(task_id)
    if not task:
        raise HTTPException(404, "task not found")

    path = _entry_txt_path(task_id)
    if not path.exists():
        if format == "text":
            raise HTTPException(404, f"entry result not found: {path}")
        return EntryResultResponse(
            task_id=task_id,
            path=str(path),
            exists=False,
            size=0,
            content="",
        )

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise HTTPException(500, f"failed to read entry result: {exc}")

    if format == "text":
        return PlainTextResponse(content, media_type="text/plain; charset=utf-8")

    return EntryResultResponse(
        task_id=task_id,
        path=str(path),
        exists=True,
        size=path.stat().st_size,
        content=content,
    )
