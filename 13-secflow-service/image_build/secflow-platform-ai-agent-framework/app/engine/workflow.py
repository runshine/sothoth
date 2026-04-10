from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from app.artifacts.io import (
    abs_path,
    ensure_dir,
    load_task_manifest,
    read_json,
    sanitize_name,
    write_json,
    write_task_manifest,
    write_text,
)
from app.artifacts.workspace import WorkspaceLayout
from app.engine.prompting import build_json_phase_prompt, build_text_phase_prompt, extract_json_payload, render_prompt
from app.models.config_models import AtomicWorkflowConfig, CompositeStageConfig, CompositeWorkflowConfig, FrameworkConfig, ReviewerBinding
from app.models.contracts import (
    AtomicResult,
    CompositeResult,
    ExecutionState,
    PluginResult,
    PluginStatus,
    ResultArtifact,
    ResultsManifest,
    ReviewArtifact,
    ReviewDecision,
    StageSummary,
    StageTaskRecord,
    SummaryArtifact,
    TaskFailurePolicy,
    TaskItem,
    WorkflowKind,
)
from app.plugins.base import PluginExecutionContext
from app.plugins.loader import PluginLoader
from app.runtime.registry import RuntimeManager

logger = logging.getLogger(__name__)


class RetryWorkflowError(RuntimeError):
    pass


class ExitWorkflowError(RuntimeError):
    pass


@dataclass
class PluginPhaseOutcome:
    end_phase_early: bool = False
    stage_state: ExecutionState | None = None
    message: str = ""


class WorkflowExecutor:
    def __init__(self, framework_config: FrameworkConfig):
        self.framework_config = framework_config
        self.runtime_manager = RuntimeManager(framework_config)
        self.plugin_loader = PluginLoader(framework_config)
        self.workspace = None
        self.atomic_by_id = {workflow.id: workflow for workflow in framework_config.atomic_workflows}
        self.composite_by_id = {workflow.id: workflow for workflow in framework_config.composite_workflows}

    def check_interruption(
        self,
        *,
        checkpoint: str,
        stage_id: str | None = None,
        task: TaskItem | None = None,
        round_no: int | None = None,
        task_dir: Path | None = None,
    ) -> None:
        return None

    def on_stage_started(self, *, workflow_config: CompositeWorkflowConfig, stage: CompositeStageConfig, stage_dir: Path, tasks: List[TaskItem]) -> None:
        return None

    def on_stage_completed(self, *, workflow_config: CompositeWorkflowConfig, stage: CompositeStageConfig, stage_dir: Path, task_records: List[StageTaskRecord]) -> None:
        return None

    def on_round_started(self, *, workflow_config: AtomicWorkflowConfig, task: TaskItem, round_no: int, round_dir: Path) -> None:
        return None

    def on_round_feedback(
        self,
        *,
        workflow_config: AtomicWorkflowConfig,
        task: TaskItem,
        round_no: int,
        feedback_path: Path,
        feedback_scope: str,
    ) -> None:
        return None

    def on_round_completed(
        self,
        *,
        workflow_config: AtomicWorkflowConfig,
        task: TaskItem,
        round_no: int,
        state: ExecutionState,
        message: str,
        task_dir: Path,
    ) -> None:
        return None

    def on_plugin_completed(
        self,
        *,
        plugin_id: str,
        phase: str,
        ctx: PluginExecutionContext,
        result: PluginResult,
        log_path: Path,
    ) -> None:
        return None

    def run(self, input_manifest_path: str, workspace_root: str) -> CompositeResult:
        self.workspace = WorkspaceLayout(workspace_root)
        manifest = load_task_manifest(input_manifest_path)
        root_dir = self.workspace.root_workflow_dir(self.framework_config.root_workflow_id)
        try:
            result = self.execute_composite(
                workflow_config=self.composite_by_id[self.framework_config.root_workflow_id],
                tasks=manifest.tasks,
                workflow_dir=root_dir,
            )
        finally:
            self.runtime_manager.close_all()
        return result

    def execute_composite(
        self,
        *,
        workflow_config: CompositeWorkflowConfig,
        tasks: List[TaskItem],
        workflow_dir: Path,
    ) -> CompositeResult:
        current_tasks = list(tasks)
        ordered_stages = self._ordered_stages(workflow_config)
        for stage in ordered_stages:
            self.check_interruption(checkpoint="before_stage", stage_id=stage.id)
            stage_dir = self.workspace.stage_dir(workflow_dir, stage.id)
            self.on_stage_started(workflow_config=workflow_config, stage=stage, stage_dir=stage_dir, tasks=current_tasks)
            next_tasks: List[TaskItem] = []
            task_records: List[StageTaskRecord] = []
            for task in current_tasks:
                self.check_interruption(checkpoint="before_task", stage_id=stage.id, task=task)
                task_dir = self.workspace.task_dir(stage_dir, sanitize_name(task.task_id))
                stage_task = self._materialize_task_input(task=task, task_dir=task_dir)
                try:
                    if stage.workflow_kind == WorkflowKind.ATOMIC:
                        result = self.execute_atomic(
                            workflow_config=self.atomic_by_id[stage.workflow_ref],
                            task=stage_task,
                            task_dir=task_dir,
                        )
                    else:
                        nested_dir = self.workspace.nested_composite_dir(task_dir, stage.workflow_ref)
                        result = self.execute_composite(
                            workflow_config=self.composite_by_id[stage.workflow_ref],
                            tasks=[stage_task],
                            workflow_dir=nested_dir,
                        )
                    manifest = load_task_manifest(result.next_tasks_manifest_path if isinstance(result, AtomicResult) else result.output_manifest_path)
                    next_tasks.extend(manifest.tasks)
                    task_records.append(
                        StageTaskRecord(
                            task_id=stage_task.task_id,
                            state=result.state,
                            message=getattr(result, "message", ""),
                            produced_task_count=len(manifest.tasks),
                            task_dir=abs_path(task_dir),
                        )
                    )
                    if result.state == ExecutionState.FAILED and stage.task_failure_policy == TaskFailurePolicy.FAIL_FAST:
                        self._write_stage_summary(stage_dir, stage, task_records)
                        self.on_stage_completed(workflow_config=workflow_config, stage=stage, stage_dir=stage_dir, task_records=task_records)
                        raise RuntimeError(f"task {task.task_id} failed in stage {stage.id}")
                except ExitWorkflowError as exc:
                    task_records.append(
                        StageTaskRecord(
                            task_id=stage_task.task_id,
                            state=ExecutionState.EXITED,
                            message=str(exc),
                            produced_task_count=0,
                            task_dir=abs_path(task_dir),
                        )
                    )
                    self._write_stage_summary(stage_dir, stage, task_records)
                    self.on_stage_completed(workflow_config=workflow_config, stage=stage, stage_dir=stage_dir, task_records=task_records)
                    raise
                except Exception as exc:
                    logger.exception("stage task execution failed: %s", exc)
                    task_records.append(
                        StageTaskRecord(
                            task_id=stage_task.task_id,
                            state=ExecutionState.FAILED,
                            message=str(exc),
                            produced_task_count=0,
                            task_dir=abs_path(task_dir),
                        )
                    )
                    if stage.task_failure_policy == TaskFailurePolicy.FAIL_FAST:
                        self._write_stage_summary(stage_dir, stage, task_records)
                        self.on_stage_completed(workflow_config=workflow_config, stage=stage, stage_dir=stage_dir, task_records=task_records)
                        raise
                self.check_interruption(checkpoint="after_task", stage_id=stage.id, task=task, task_dir=task_dir)
            self._write_stage_summary(stage_dir, stage, task_records)
            self.on_stage_completed(workflow_config=workflow_config, stage=stage, stage_dir=stage_dir, task_records=task_records)
            current_tasks = next_tasks

        manifest_path = write_task_manifest(Path(workflow_dir) / "next_tasks" / "manifest.json", current_tasks)
        return CompositeResult(
            state=ExecutionState.SUCCEEDED,
            output_manifest_path=abs_path(manifest_path),
            output_task_count=len(current_tasks),
            workflow_dir=abs_path(workflow_dir),
        )

    def _materialize_task_input(self, *, task: TaskItem, task_dir: Path) -> TaskItem:
        input_dir = ensure_dir(task_dir / "input")
        source_path = Path(task.task_md_path)
        if not source_path.exists():
            raise FileNotFoundError(f"task markdown not found: {task.task_md_path}")
        task_md_path = write_text(input_dir / source_path.name, source_path.read_text(encoding="utf-8"))
        write_json(
            input_dir / "task.json",
            {
                "task_id": task.task_id,
                "task_type": task.task_type,
                "title": task.title,
                "metadata": task.metadata,
                "upstream_refs": task.upstream_refs,
                "source_task_md_path": task.task_md_path,
            },
        )
        return task.model_copy(update={"task_md_path": abs_path(task_md_path)})

    def execute_atomic(self, *, workflow_config: AtomicWorkflowConfig, task: TaskItem, task_dir: Path) -> AtomicResult:
        if task.task_type != workflow_config.input_task_type:
            raise ValueError(f"task {task.task_id} type {task.task_type} does not match expected {workflow_config.input_task_type}")

        for attempt_no in range(1, workflow_config.max_restart_attempts + 2):
            attempt_dir = ensure_dir(task_dir / f"attempt-{attempt_no:03d}")
            self.check_interruption(checkpoint="before_attempt", task=task, task_dir=attempt_dir)
            try:
                return self._execute_atomic_attempt(workflow_config=workflow_config, task=task, task_dir=attempt_dir)
            except RetryWorkflowError as exc:
                write_json(
                    attempt_dir / "retry.json",
                    {"attempt_no": attempt_no, "message": str(exc)},
                )
                if attempt_no > workflow_config.max_restart_attempts:
                    manifest_path = self._write_empty_next_tasks_manifest(attempt_dir)
                    return AtomicResult(
                        state=ExecutionState.FAILED,
                        next_tasks_manifest_path=abs_path(manifest_path),
                        next_task_count=0,
                        task_dir=abs_path(attempt_dir),
                        message=f"retry limit exceeded: {exc}",
                    )
                continue
            finally:
                self.runtime_manager.close_task_scope(f"{workflow_config.id}:{task.task_id}:worker")

        manifest_path = self._write_empty_next_tasks_manifest(task_dir)
        return AtomicResult(
            state=ExecutionState.FAILED,
            next_tasks_manifest_path=abs_path(manifest_path),
            next_task_count=0,
            task_dir=abs_path(task_dir),
            message="unreachable retry state",
        )

    def _execute_atomic_attempt(self, *, workflow_config: AtomicWorkflowConfig, task: TaskItem, task_dir: Path) -> AtomicResult:
        shared_state: Dict[str, Any] = {}
        self.check_interruption(checkpoint="before_pre_plugins", task=task, task_dir=task_dir)
        pre_ctx = PluginExecutionContext(
            framework_config=self.framework_config,
            workflow_config=workflow_config,
            plugin_definition=None,
            phase="pre",
            task=task,
            task_dir=task_dir,
            workspace_root=self.workspace.workspace_root,
            round_no=0,
            runtime_manager=self.runtime_manager,
            shared_state=shared_state,
        )
        pre_outcome = self._run_plugin_phase(plugin_ids=workflow_config.pre_plugins, ctx=pre_ctx, phase_dir=task_dir / "plugin_runs" / "pre")
        if pre_outcome.stage_state == ExecutionState.ABNORMAL_CONTINUE:
            manifest_path = self._write_empty_next_tasks_manifest(task_dir)
            return AtomicResult(
                state=ExecutionState.ABNORMAL_CONTINUE,
                next_tasks_manifest_path=abs_path(manifest_path),
                next_task_count=0,
                task_dir=abs_path(task_dir),
                message=pre_outcome.message,
            )

        passed_result_reviews: Dict[Tuple[str, str], ReviewArtifact] = {}
        feedback_path: Path | None = None
        summary_json_path: Path | None = None
        results_manifest_path: Path | None = None

        for round_no in range(1, workflow_config.max_rounds + 1):
            round_dir = ensure_dir(task_dir / f"round-{round_no:03d}")
            self.check_interruption(checkpoint="before_round", task=task, round_no=round_no, task_dir=round_dir)
            self.on_round_started(workflow_config=workflow_config, task=task, round_no=round_no, round_dir=round_dir)
            worker_scope = f"{workflow_config.id}:{task.task_id}:worker"
            render_ctx = self._base_prompt_context(
                workflow_config=workflow_config,
                task=task,
                task_dir=task_dir,
                round_no=round_no,
                feedback_path=feedback_path,
                summary_json_path=summary_json_path,
                results_manifest_path=results_manifest_path,
            )

            worker_prompt = render_prompt(self.framework_config.prompts[workflow_config.worker.task_prompt_ref], render_ctx)
            worker_response = self.runtime_manager.run_prompt(
                agent_instance_id=workflow_config.worker.agent_instance_id,
                prompt=build_text_phase_prompt(
                    phase="worker",
                    user_prompt=worker_prompt,
                    context=render_ctx,
                ),
                task_scope=worker_scope,
                session_mode_override=workflow_config.worker.session_mode_override,
                cwd_override=abs_path(task_dir),
            )
            if not worker_response.success:
                raise RuntimeError(worker_response.error or "worker failed")
            write_text(round_dir / "worker" / "response.md", worker_response.output)

            for index, prompt_ref in enumerate(workflow_config.reflection_prompt_refs, start=1):
                reflection_prompt = render_prompt(self.framework_config.prompts[prompt_ref], render_ctx)
                reflection_response = self.runtime_manager.run_prompt(
                    agent_instance_id=workflow_config.worker.agent_instance_id,
                    prompt=build_text_phase_prompt(
                        phase="reflection",
                        user_prompt=reflection_prompt,
                        context=render_ctx,
                    ),
                    task_scope=worker_scope,
                    session_mode_override=workflow_config.worker.session_mode_override,
                    cwd_override=abs_path(task_dir),
                )
                if not reflection_response.success:
                    raise RuntimeError(reflection_response.error or "reflection failed")
                write_text(round_dir / "reflections" / f"{index:03d}-{sanitize_name(prompt_ref)}.md", reflection_response.output)

            summary_paths = self._execute_summary(
                workflow_config=workflow_config,
                task=task,
                task_dir=task_dir,
                round_dir=round_dir,
                round_no=round_no,
                render_ctx=render_ctx,
                worker_scope=worker_scope,
            )
            summary_json_path = summary_paths["summary_json_path"]
            results_manifest_path = summary_paths["results_manifest_path"]

            global_reviews = self._run_global_reviews(
                workflow_config=workflow_config,
                task=task,
                task_dir=task_dir,
                round_no=round_no,
                summary_json_path=summary_json_path,
                results_manifest_path=results_manifest_path,
                feedback_json_path=feedback_path,
            )
            global_failures = [item for item in global_reviews if item.decision == ReviewDecision.FAIL]
            if global_failures:
                feedback_path = self._write_feedback(task_dir, round_no, global_failures, [])
                self.on_round_feedback(
                    workflow_config=workflow_config,
                    task=task,
                    round_no=round_no,
                    feedback_path=feedback_path,
                    feedback_scope="global",
                )
                continue

            result_failures = self._run_result_reviews(
                workflow_config=workflow_config,
                task=task,
                task_dir=task_dir,
                round_no=round_no,
                results_manifest_path=results_manifest_path,
                passed_result_reviews=passed_result_reviews,
                feedback_json_path=feedback_path,
            )
            if result_failures:
                feedback_path = self._write_feedback(task_dir, round_no, [], result_failures)
                self.on_round_feedback(
                    workflow_config=workflow_config,
                    task=task,
                    round_no=round_no,
                    feedback_path=feedback_path,
                    feedback_scope="result",
                )
                continue

            self.check_interruption(checkpoint="before_post_plugins", task=task, round_no=round_no, task_dir=round_dir)
            post_ctx = PluginExecutionContext(
                framework_config=self.framework_config,
                workflow_config=workflow_config,
                plugin_definition=None,
                phase="post",
                task=task,
                task_dir=task_dir,
                workspace_root=self.workspace.workspace_root,
                round_no=round_no,
                runtime_manager=self.runtime_manager,
                shared_state=shared_state,
                summary_json_path=summary_json_path,
                results_manifest_path=results_manifest_path,
                feedback_json_path=feedback_path,
            )
            post_outcome = self._run_plugin_phase(
                plugin_ids=workflow_config.post_plugins,
                ctx=post_ctx,
                phase_dir=task_dir / "plugin_runs" / "post",
            )
            if post_outcome.stage_state == ExecutionState.ABNORMAL_CONTINUE:
                manifest_path = self._write_empty_next_tasks_manifest(task_dir)
                return AtomicResult(
                    state=ExecutionState.ABNORMAL_CONTINUE,
                    next_tasks_manifest_path=abs_path(manifest_path),
                    next_task_count=0,
                    task_dir=abs_path(task_dir),
                    message=post_outcome.message,
                )

            builtin_ctx = post_ctx
            builtin_ctx.next_task_manifest_path = task_dir / "next_tasks" / "manifest.json"
            builtin_outcome = self._run_plugin_phase(
                plugin_ids=["builtin.next_task_generator"],
                ctx=builtin_ctx,
                phase_dir=task_dir / "plugin_runs" / "post-builtin",
            )
            if builtin_outcome.stage_state == ExecutionState.ABNORMAL_CONTINUE:
                manifest_path = self._write_empty_next_tasks_manifest(task_dir)
                return AtomicResult(
                    state=ExecutionState.ABNORMAL_CONTINUE,
                    next_tasks_manifest_path=abs_path(manifest_path),
                    next_task_count=0,
                    task_dir=abs_path(task_dir),
                    message=builtin_outcome.message,
                )
            next_tasks_manifest_path = builtin_ctx.next_task_manifest_path or self._write_empty_next_tasks_manifest(task_dir)
            next_tasks = load_task_manifest(next_tasks_manifest_path).tasks
            self.on_round_completed(
                workflow_config=workflow_config,
                task=task,
                round_no=round_no,
                state=ExecutionState.SUCCEEDED,
                message="atomic workflow succeeded",
                task_dir=task_dir,
            )
            return AtomicResult(
                state=ExecutionState.SUCCEEDED,
                next_tasks_manifest_path=abs_path(next_tasks_manifest_path),
                next_task_count=len(next_tasks),
                task_dir=abs_path(task_dir),
                message="atomic workflow succeeded",
            )

        manifest_path = self._write_empty_next_tasks_manifest(task_dir)
        self.on_round_completed(
            workflow_config=workflow_config,
            task=task,
            round_no=workflow_config.max_rounds,
            state=ExecutionState.FAILED,
            message="max_rounds exhausted",
            task_dir=task_dir,
        )
        return AtomicResult(
            state=ExecutionState.FAILED,
            next_tasks_manifest_path=abs_path(manifest_path),
            next_task_count=0,
            task_dir=abs_path(task_dir),
            message="max_rounds exhausted",
        )

    def _execute_summary(
        self,
        *,
        workflow_config: AtomicWorkflowConfig,
        task: TaskItem,
        task_dir: Path,
        round_dir: Path,
        round_no: int,
        render_ctx: Dict[str, Any],
        worker_scope: str,
    ) -> Dict[str, Path]:
        summary_prompt = render_prompt(self.framework_config.prompts[workflow_config.summary.prompt_ref], render_ctx)
        summary_response = self.runtime_manager.run_prompt(
            agent_instance_id=workflow_config.worker.agent_instance_id,
            prompt=build_json_phase_prompt(
                phase="summary",
                user_prompt=summary_prompt,
                context=render_ctx,
                schema_hint={
                    "summary_markdown": "string",
                    "summary_json": {
                        "task_status": "completed",
                        "next_stage_hints": [],
                    },
                    "results": [
                        {
                            "result_id": "result-001",
                            "title": "string",
                            "markdown": "string",
                            "json": {},
                            "metadata": {},
                        }
                    ],
                },
            ),
            task_scope=worker_scope,
            session_mode_override=workflow_config.worker.session_mode_override,
            cwd_override=abs_path(task_dir),
        )
        if not summary_response.success:
            raise RuntimeError(summary_response.error or "summary failed")
        payload = extract_json_payload(summary_response.output)
        summary_md_path = write_text(round_dir / "summary.md", str(payload.get("summary_markdown", "")).strip() + "\n")
        results_dir = ensure_dir(round_dir / "results")
        result_items: List[ResultArtifact] = []
        for index, item in enumerate(payload.get("results", []), start=1):
            result_id = str(item.get("result_id") or f"{task.task_id}-result-{index:03d}")
            title = str(item.get("title") or result_id)
            md_path = write_text(results_dir / f"{sanitize_name(result_id)}.md", str(item.get("markdown", "")).strip() + "\n")
            json_path = write_json(
                results_dir / f"{sanitize_name(result_id)}.json",
                {
                    "result_id": result_id,
                    "title": title,
                    "metadata": item.get("metadata", {}),
                    "content": item.get("json", {}),
                },
            )
            result_items.append(
                ResultArtifact(
                    result_id=result_id,
                    title=title,
                    result_md_path=abs_path(md_path),
                    result_json_path=abs_path(json_path),
                    metadata=dict(item.get("metadata", {})),
                )
            )
        results_manifest_path = write_json(
            results_dir / "manifest.json",
            ResultsManifest(result_count=len(result_items), items=result_items).model_dump(mode="json"),
        )
        summary_json = SummaryArtifact(
            task_status=str(payload.get("summary_json", {}).get("task_status", "completed")),
            summary_md_path=abs_path(summary_md_path),
            results_manifest_path=abs_path(results_manifest_path),
            result_count=len(result_items),
            next_stage_hints=list(payload.get("summary_json", {}).get("next_stage_hints", [])),
        )
        summary_json_path = write_json(round_dir / "summary.json", summary_json.model_dump(mode="json"))
        return {
            "summary_md_path": summary_md_path,
            "summary_json_path": summary_json_path,
            "results_manifest_path": results_manifest_path,
        }

    def _run_global_reviews(
        self,
        *,
        workflow_config: AtomicWorkflowConfig,
        task: TaskItem,
        task_dir: Path,
        round_no: int,
        summary_json_path: Path,
        results_manifest_path: Path,
        feedback_json_path: Path | None,
    ) -> List[ReviewArtifact]:
        artifacts: List[ReviewArtifact] = []
        for reviewer in workflow_config.advisor.global_reviewers:
            rerun = reviewer.rerun_on_next_round if reviewer.rerun_on_next_round is not None else True
            review = self._execute_reviewer(
                reviewer=reviewer,
                scope="global",
                target_id=task.task_id,
                task=task,
                workflow_config=workflow_config,
                round_no=round_no,
                task_dir=task_dir,
                summary_json_path=summary_json_path,
                results_manifest_path=results_manifest_path,
                review_dir=task_dir / "reviews" / "global" / sanitize_name(reviewer.id),
                result_md_path=None,
                result_json_path=None,
                feedback_json_path=feedback_json_path,
                rerun_on_next_round=rerun,
            )
            artifacts.append(review)
            if review.decision == ReviewDecision.FAIL:
                break
        return artifacts

    def _run_result_reviews(
        self,
        *,
        workflow_config: AtomicWorkflowConfig,
        task: TaskItem,
        task_dir: Path,
        round_no: int,
        results_manifest_path: Path,
        passed_result_reviews: Dict[Tuple[str, str], ReviewArtifact],
        feedback_json_path: Path | None,
    ) -> List[ReviewArtifact]:
        manifest = ResultsManifest.model_validate(read_json(results_manifest_path))
        failures: List[ReviewArtifact] = []
        cache_lock = threading.Lock()

        def review_single_result(result_item: ResultArtifact) -> List[ReviewArtifact]:
            local_artifacts: List[ReviewArtifact] = []
            for reviewer in workflow_config.advisor.result_reviewers:
                rerun = reviewer.rerun_on_next_round if reviewer.rerun_on_next_round is not None else False
                cache_key = (result_item.result_id, reviewer.id)
                with cache_lock:
                    cached = cache_key in passed_result_reviews
                if not rerun and cached:
                    continue
                review = self._execute_reviewer(
                    reviewer=reviewer,
                    scope="result",
                    target_id=result_item.result_id,
                    task=task,
                    workflow_config=workflow_config,
                    round_no=round_no,
                    task_dir=task_dir,
                    summary_json_path=None,
                    results_manifest_path=results_manifest_path,
                    review_dir=task_dir / "reviews" / "results" / sanitize_name(result_item.result_id) / sanitize_name(reviewer.id),
                    result_md_path=Path(result_item.result_md_path),
                    result_json_path=Path(result_item.result_json_path),
                    feedback_json_path=feedback_json_path,
                    rerun_on_next_round=rerun,
                )
                local_artifacts.append(review)
                if review.decision == ReviewDecision.PASS and not rerun:
                    with cache_lock:
                        passed_result_reviews[cache_key] = review
                if review.decision == ReviewDecision.FAIL:
                    break
            return local_artifacts

        with ThreadPoolExecutor(max_workers=max(1, len(manifest.items))) as executor:
            futures = {executor.submit(review_single_result, item): item.result_id for item in manifest.items}
            for future in as_completed(futures):
                for artifact in future.result():
                    if artifact.decision == ReviewDecision.FAIL:
                        failures.append(artifact)
        return failures

    def _execute_reviewer(
        self,
        *,
        reviewer: ReviewerBinding,
        scope: str,
        target_id: str,
        task: TaskItem,
        workflow_config: AtomicWorkflowConfig,
        round_no: int,
        task_dir: Path,
        summary_json_path: Path | None,
        results_manifest_path: Path,
        review_dir: Path,
        result_md_path: Path | None,
        result_json_path: Path | None,
        feedback_json_path: Path | None,
        rerun_on_next_round: bool,
    ) -> ReviewArtifact:
        prompt_context = {
            "task_md_path": task.task_md_path,
            "task_metadata": task.metadata,
            "workspace_root": abs_path(self.workspace.workspace_root),
            "current_round": round_no,
            "failed_feedback_json_path": abs_path(feedback_json_path) if feedback_json_path else "",
            "summary_md_path": "",
            "summary_json_path": abs_path(summary_json_path) if summary_json_path else "",
            "results_manifest_path": abs_path(results_manifest_path),
            "result_md_path": abs_path(result_md_path) if result_md_path else "",
            "result_json_path": abs_path(result_json_path) if result_json_path else "",
            "task_id": task.task_id,
            "task_title": task.title,
            "task_type": task.task_type,
            "output_task_type": workflow_config.output_task_type,
            "result_id": target_id,
        }
        system_prompt = render_prompt(self.framework_config.prompts[reviewer.system_prompt_ref], prompt_context)
        user_prompt = render_prompt(self.framework_config.prompts[reviewer.user_prompt_ref], prompt_context)
        response = self.runtime_manager.run_prompt(
            agent_instance_id=reviewer.agent_instance_id,
            prompt=build_json_phase_prompt(
                phase="global_review" if scope == "global" else "result_review",
                user_prompt=user_prompt,
                context=prompt_context,
                schema_hint={
                    "report_markdown": "string",
                    "decision": "pass|fail",
                    "blocking_issues": [],
                    "feedback_to_worker": [],
                    "needs_rerun_next_round": True,
                },
                system_prompt=system_prompt,
            ),
            task_scope=f"{workflow_config.id}:{task.task_id}:{scope}:{reviewer.id}:{target_id}",
            force_new_session=True,
            cwd_override=abs_path(task_dir),
        )
        if not response.success:
            raise RuntimeError(response.error or f"{scope} review failed")
        payload = extract_json_payload(response.output)
        review_dir = ensure_dir(review_dir)
        report_md_path = write_text(review_dir / f"round-{round_no:03d}.md", str(payload.get("report_markdown", "")).strip() + "\n")
        artifact = ReviewArtifact(
            decision=ReviewDecision(str(payload.get("decision", "fail")).lower()),
            scope=scope,
            target_id=target_id,
            blocking_issues=list(payload.get("blocking_issues", [])),
            feedback_to_worker=list(payload.get("feedback_to_worker", [])),
            needs_rerun_next_round=rerun_on_next_round,
        )
        write_json(review_dir / f"round-{round_no:03d}.json", artifact.model_dump(mode="json"))
        return artifact

    def _run_plugin_phase(self, *, plugin_ids: Iterable[str], ctx: PluginExecutionContext, phase_dir: Path) -> PluginPhaseOutcome:
        ensure_dir(phase_dir)
        for index, plugin_id in enumerate(plugin_ids, start=1):
            plugin = self.plugin_loader.resolve(plugin_id)
            ctx.plugin_definition = getattr(plugin, "plugin_definition", None)
            try:
                result = plugin.execute(ctx)
            except RetryWorkflowError:
                raise
            except ExitWorkflowError:
                raise
            except Exception as exc:
                result = PluginResult(status=PluginStatus.FAIL_EXIT_WORKFLOW, message=str(exc))

            write_json(
                phase_dir / f"{index:03d}-{sanitize_name(plugin_id)}.json",
                {
                    "plugin_id": plugin_id,
                    "status": result.status.value,
                    "message": result.message,
                    "payload": result.payload,
                },
            )
            log_path = phase_dir / f"{index:03d}-{sanitize_name(plugin_id)}.json"
            self.on_plugin_completed(plugin_id=plugin_id, phase=ctx.phase, ctx=ctx, result=result, log_path=log_path)
            self.check_interruption(
                checkpoint="after_plugin",
                stage_id=None,
                task=ctx.task,
                round_no=ctx.round_no,
                task_dir=ctx.task_dir,
            )
            if result.status == PluginStatus.SUCCESS_NEXT:
                continue
            if result.status == PluginStatus.FAIL_CONTINUE_NEXT_PLUGIN:
                continue
            if result.status == PluginStatus.SUCCESS_END_STAGE:
                return PluginPhaseOutcome(end_phase_early=True, message=result.message)
            if result.status == PluginStatus.RETRY_WORKFLOW:
                raise RetryWorkflowError(result.message or plugin_id)
            if result.status == PluginStatus.FAIL_END_STAGE_CONTINUE:
                return PluginPhaseOutcome(stage_state=ExecutionState.ABNORMAL_CONTINUE, message=result.message)
            if result.status == PluginStatus.FAIL_EXIT_WORKFLOW:
                raise ExitWorkflowError(result.message or plugin_id)
        return PluginPhaseOutcome()

    def _base_prompt_context(
        self,
        *,
        workflow_config: AtomicWorkflowConfig,
        task: TaskItem,
        task_dir: Path,
        round_no: int,
        feedback_path: Path | None,
        summary_json_path: Path | None,
        results_manifest_path: Path | None,
    ) -> Dict[str, Any]:
        return {
            "task_md_path": task.task_md_path,
            "task_metadata": task.metadata,
            "workspace_root": abs_path(self.workspace.workspace_root),
            "current_round": round_no,
            "failed_feedback_json_path": abs_path(feedback_path) if feedback_path else "",
            "summary_md_path": "",
            "summary_json_path": abs_path(summary_json_path) if summary_json_path else "",
            "results_manifest_path": abs_path(results_manifest_path) if results_manifest_path else "",
            "result_md_path": "",
            "result_json_path": "",
            "task_id": task.task_id,
            "task_title": task.title,
            "task_type": task.task_type,
            "output_task_type": workflow_config.output_task_type,
            "task_dir": abs_path(task_dir),
        }

    def _write_feedback(
        self,
        task_dir: Path,
        round_no: int,
        global_failures: List[ReviewArtifact],
        result_failures: List[ReviewArtifact],
    ) -> Path:
        feedback_path = write_json(
            task_dir / "review_feedback" / f"round-{round_no:03d}.json",
            {
                "round_no": round_no,
                "global_failures": [item.model_dump(mode="json") for item in global_failures],
                "result_failures": [item.model_dump(mode="json") for item in result_failures],
                "feedback_to_worker": [
                    *[entry for artifact in global_failures for entry in artifact.feedback_to_worker],
                    *[entry for artifact in result_failures for entry in artifact.feedback_to_worker],
                ],
            },
        )
        return feedback_path

    def _ordered_stages(self, workflow_config: CompositeWorkflowConfig) -> List[CompositeStageConfig]:
        stage_map = {stage.id: stage for stage in workflow_config.stages}
        current = next(stage for stage in workflow_config.stages if stage.previous_stage_id is None)
        ordered = []
        while current:
            ordered.append(current)
            current = stage_map.get(current.next_stage_id) if current.next_stage_id else None
        return ordered

    def _write_stage_summary(self, stage_dir: Path, stage: CompositeStageConfig, task_records: List[StageTaskRecord]) -> None:
        summary = StageSummary(
            stage_id=stage.id,
            workflow_ref=stage.workflow_ref,
            task_count=len(task_records),
            success_count=sum(1 for record in task_records if record.state == ExecutionState.SUCCEEDED),
            failure_count=sum(1 for record in task_records if record.state in {ExecutionState.FAILED, ExecutionState.EXITED}),
            produced_task_count=sum(record.produced_task_count for record in task_records),
            task_records=task_records,
        )
        write_json(stage_dir / "stage_summary.json", summary.model_dump(mode="json"))

    def _write_empty_next_tasks_manifest(self, task_dir: Path) -> Path:
        return write_task_manifest(Path(task_dir) / "next_tasks" / "manifest.json", [])
