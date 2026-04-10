from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SessionMode(str, Enum):
    INVOKE = "invoke"
    PIPE = "pipe"
    PTY = "pty"


class PluginStatus(str, Enum):
    SUCCESS_NEXT = "SUCCESS_NEXT"
    SUCCESS_END_STAGE = "SUCCESS_END_STAGE"
    RETRY_WORKFLOW = "RETRY_WORKFLOW"
    FAIL_END_STAGE_CONTINUE = "FAIL_END_STAGE_CONTINUE"
    FAIL_EXIT_WORKFLOW = "FAIL_EXIT_WORKFLOW"
    FAIL_CONTINUE_NEXT_PLUGIN = "FAIL_CONTINUE_NEXT_PLUGIN"


class WorkflowKind(str, Enum):
    ATOMIC = "atomic"
    COMPOSITE = "composite"


class TaskFailurePolicy(str, Enum):
    FAIL_FAST = "fail_fast"
    CONTINUE = "continue"


class ExecutionState(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ABNORMAL_CONTINUE = "abnormal_continue"
    EXITED = "exited"


class ReviewDecision(str, Enum):
    PASS = "pass"
    FAIL = "fail"


class TaskItem(StrictModel):
    task_id: str = Field(..., min_length=1)
    task_type: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    task_md_path: str = Field(..., min_length=1)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    upstream_refs: List[str] = Field(default_factory=list)


class TaskManifest(StrictModel):
    tasks: List[TaskItem] = Field(default_factory=list)


class ResultArtifact(StrictModel):
    result_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    result_md_path: str = Field(..., min_length=1)
    result_json_path: str = Field(..., min_length=1)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ResultsManifest(StrictModel):
    result_count: int = Field(default=0, ge=0)
    items: List[ResultArtifact] = Field(default_factory=list)


class SummaryArtifact(StrictModel):
    task_status: str = Field(..., min_length=1)
    summary_md_path: str = Field(..., min_length=1)
    results_manifest_path: str = Field(..., min_length=1)
    result_count: int = Field(default=0, ge=0)
    next_stage_hints: List[str] = Field(default_factory=list)


class ReviewArtifact(StrictModel):
    decision: ReviewDecision
    scope: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    blocking_issues: List[str] = Field(default_factory=list)
    feedback_to_worker: List[str] = Field(default_factory=list)
    needs_rerun_next_round: bool = False


class PluginResult(StrictModel):
    status: PluginStatus
    message: str = ""
    payload: Dict[str, Any] = Field(default_factory=dict)


class NextTaskDraft(StrictModel):
    title: str = Field(..., min_length=1)
    body_markdown: str = Field(..., min_length=1)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class StageTaskRecord(StrictModel):
    task_id: str
    state: ExecutionState
    message: str = ""
    produced_task_count: int = 0
    task_dir: str


class StageSummary(StrictModel):
    stage_id: str
    workflow_ref: str
    task_count: int
    success_count: int
    failure_count: int
    produced_task_count: int
    task_records: List[StageTaskRecord] = Field(default_factory=list)


class CompositeResult(StrictModel):
    state: ExecutionState
    output_manifest_path: str
    output_task_count: int
    workflow_dir: str


class AtomicResult(StrictModel):
    state: ExecutionState
    next_tasks_manifest_path: str
    next_task_count: int
    task_dir: str
    message: str = ""
