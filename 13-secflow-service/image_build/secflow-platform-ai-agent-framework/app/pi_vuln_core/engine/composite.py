"""
组合工作流引擎

- 管理多阶段顺序执行 (R9)
- 一对多任务扇出 (R13)
- 支持嵌套组合工作流 (R3)
- 阶段间不可回退
"""

from __future__ import annotations

import os
from typing import Optional

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import (
    FrameworkConfig, CompositeWorkflowDef, AtomicWorkflowDef,
    StageDef, GlobalConfig,
)
from app.pi_vuln_core.engine.atomic import AtomicWorkflowEngine
from app.pi_vuln_core.engine.models import (
    CompositeWorkflowResult, AtomicWorkflowResult, TaskItem,
)
from app.pi_vuln_core.observer import ExecutionObserver, NullExecutionObserver
from app.pi_vuln_core.plugins.executor import PluginChainExecutor
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.workspace.manager import WorkspaceManager
from app.pi_vuln_core.utils.file_ops import write_json
from app.pi_vuln_core.utils.logger import get_logger
from app.pi_vuln_core.utils.visual_log import vlog

logger = get_logger("composite_engine")


class WorkflowRegistry:
    """工作流定义注册表"""

    def __init__(self, config: FrameworkConfig):
        self._atomic: dict[str, AtomicWorkflowDef] = {
            w.id: w for w in config.workflows.atomic
        }
        self._composite: dict[str, CompositeWorkflowDef] = {
            w.id: w for w in config.workflows.composite
        }

    def get_atomic(self, wf_id: str) -> AtomicWorkflowDef:
        if wf_id not in self._atomic:
            raise KeyError(f"原子工作流 '{wf_id}' 不存在")
        return self._atomic[wf_id]

    def get_composite(self, wf_id: str) -> CompositeWorkflowDef:
        if wf_id not in self._composite:
            raise KeyError(f"组合工作流 '{wf_id}' 不存在")
        return self._composite[wf_id]


class CompositeWorkflowEngine:
    """
    组合工作流引擎 (R3, R9, R11)

    - 按 stage.sequence 顺序执行各阶段
    - 阶段间传递任务列表（一对多扇出）
    - 支持嵌套组合工作流
    - 不可回退到已完成阶段
    """

    def __init__(
        self,
        config: FrameworkConfig,
        agent_registry: AgentRuntimeRegistry,
        plugin_executor: PluginChainExecutor,
        workspace: WorkspaceManager,
        recorder: ExecutionRecorder,
        observer: ExecutionObserver | None = None,
    ):
        self.config = config
        self.global_cfg = config.global_config
        self.agents = agent_registry
        self.plugin_exec = plugin_executor
        self.workspace = workspace
        self.recorder = recorder
        self.wf_registry = WorkflowRegistry(config)
        self.observer = observer or NullExecutionObserver()

    async def run(
        self,
        workflow_id: str,
        input_task_file: str,
        execution_id: str,
        parent_dir: Optional[str] = None,
    ) -> CompositeWorkflowResult:
        initial_tasks = [TaskItem(id="initial_001", file=input_task_file, source_stage="input")]
        return await self.run_tasks(
            workflow_id=workflow_id,
            tasks=initial_tasks,
            execution_id=execution_id,
            parent_dir=parent_dir,
        )

    async def run_tasks(
        self,
        workflow_id: str,
        tasks: list[TaskItem],
        execution_id: str,
        parent_dir: Optional[str] = None,
    ) -> CompositeWorkflowResult:
        """
        执行组合工作流

        Args:
            workflow_id:      组合工作流 ID
            input_task_file:  初始输入任务文件
            execution_id:     执行 ID
            parent_dir:       父目录（嵌套场景）
        """
        wf_def = self.wf_registry.get_composite(workflow_id)
        work_dir = self.workspace.create_composite_dir(
            wf_def.working_dir_template,
            parent_dir=parent_dir,
            execution_id=execution_id,
        )

        vlog.banner(f"组合工作流: {wf_def.name} ({workflow_id})")
        logger.info("composite_workflow_start",
                     workflow_id=workflow_id,
                     execution_id=execution_id,
                     stages=len(wf_def.stages),
                     work_dir=work_dir)

        # 初始任务 = [input_task_file]
        current_tasks = list(tasks)

        stages = sorted(wf_def.stages, key=lambda s: s.sequence)
        completed_stages: list[str] = []
        total_tasks = 0

        for stage in stages:
            await self.observer.check_cancel(
                "stage:before",
                workflow_id=workflow_id,
                stage_id=stage.stage_id,
                execution_id=execution_id,
            )
            stage_dir = self.workspace.create_stage_dir(
                work_dir, stage.stage_id)
            await self.observer.on_stage_started(
                workflow_id=workflow_id,
                stage_id=stage.stage_id,
                stage_name=stage.name,
                execution_id=execution_id,
                task_count=len(current_tasks),
                stage_dir=stage_dir,
            )

            vlog.stage_start(stage.stage_id, len(current_tasks))
            logger.info("stage_start",
                         stage_id=stage.stage_id,
                         stage_name=stage.name,
                         task_count=len(current_tasks))

            # 对当前任务列表逐个执行
            next_tasks: list[TaskItem] = []
            stage_errors: list[tuple[TaskItem, str]] = []

            for task_idx, task_item in enumerate(current_tasks):
                total_tasks += 1
                logger.info("stage_task_start",
                             stage_id=stage.stage_id,
                             task_idx=task_idx + 1,
                             task_id=task_item.id,
                             total_in_stage=len(current_tasks))

                try:
                    result = await self._execute_stage_task(
                        stage, task_item, stage_dir)

                    if result.success and result.next_tasks:
                        next_tasks.extend(result.next_tasks)
                        logger.info("stage_task_done",
                                     task_id=task_item.id,
                                     next_tasks=len(result.next_tasks))
                    elif not result.success:
                        stage_errors.append((task_item, result.error or "未知错误"))
                        logger.warning("stage_task_failed",
                                       task_id=task_item.id,
                                       error=result.error)

                except Exception as e:
                    stage_errors.append((task_item, str(e)))
                    logger.error("stage_task_exception",
                                 task_id=task_item.id, error=str(e))

            # 处理阶段错误
            if stage_errors:
                should_abort = await self._handle_stage_errors(
                    stage, stage_errors, work_dir, execution_id)

                if should_abort:
                    await self.observer.on_stage_failed(
                        workflow_id=workflow_id,
                        stage_id=stage.stage_id,
                        execution_id=execution_id,
                        error_summary=error_summary,
                        stage_dir=stage_dir,
                    )
                    return CompositeWorkflowResult(
                        status="failed",
                        error=f"Stage {stage.stage_id} 失败, 策略={stage.on_error}",
                        working_dir=work_dir,
                        completed_stages=completed_stages,
                        total_stages=len(stages),
                        total_tasks_processed=total_tasks,
                    )

            completed_stages.append(stage.stage_id)

            vlog.stage_done(stage.stage_id, len(next_tasks), len(stage_errors))
            logger.info("stage_done",
                         stage_id=stage.stage_id,
                         output_tasks=len(next_tasks),
                         errors=len(stage_errors))
            await self.observer.on_stage_completed(
                workflow_id=workflow_id,
                stage_id=stage.stage_id,
                execution_id=execution_id,
                output_task_count=len(next_tasks),
                error_count=len(stage_errors),
                stage_dir=stage_dir,
            )

            # 阶段间任务传递
            if not next_tasks:
                logger.warning("stage_no_output",
                               stage_id=stage.stage_id,
                               msg="后续阶段无法执行")
                break

            current_tasks = next_tasks

        # 写入执行总结
        summary = CompositeWorkflowResult(
            status="completed",
            final_tasks=current_tasks,
            working_dir=work_dir,
            completed_stages=completed_stages,
            total_stages=len(stages),
            total_tasks_processed=total_tasks,
        )

        write_json(
            os.path.join(work_dir, "_meta", "workflow_result.json"),
            summary.to_dict())

        logger.info("composite_workflow_done",
                     workflow_id=workflow_id,
                     status="completed",
                     stages_completed=len(completed_stages),
                     final_tasks=len(current_tasks))

        return summary

    async def _execute_stage_task(
        self,
        stage: StageDef,
        task_item: TaskItem,
        stage_dir: str,
    ) -> AtomicWorkflowResult:
        """执行单个阶段中的单个任务"""

        if stage.workflow_type == "atomic":
            wf_def = self.wf_registry.get_atomic(stage.workflow_ref)
            engine = AtomicWorkflowEngine(
                wf_def=wf_def,
                agent_registry=self.agents,
                plugin_executor=self.plugin_exec,
                workspace=self.workspace,
                recorder=self.recorder,
                global_config=self.global_cfg,
                observer=self.observer,
            )
            return await engine.run(
                task_file=task_item.file,
                task_id=task_item.id,
                parent_dir=stage_dir,
            )

        elif stage.workflow_type == "composite":
            # 嵌套组合工作流 (R3)
            sub_exec_id = f"{task_item.id}_{stage.workflow_ref}"
            sub_result = await self.run(
                workflow_id=stage.workflow_ref,
                input_task_file=task_item.file,
                execution_id=sub_exec_id,
                parent_dir=stage_dir,
            )
            # 转换为 AtomicWorkflowResult 格式
            return AtomicWorkflowResult(
                status=sub_result.status,
                next_tasks=sub_result.final_tasks,
                working_dir=sub_result.working_dir,
                error=sub_result.error,
            )

        else:
            raise ValueError(f"未知的 workflow_type: {stage.workflow_type}")

    async def _handle_stage_errors(
        self,
        stage: StageDef,
        errors: list[tuple[TaskItem, str]],
        work_dir: str,
        execution_id: str,
    ) -> bool:
        """
        处理阶段错误

        Returns: True=应终止整个组合工作流, False=可继续
        """
        error_summary = "; ".join(
            f"{t.id}: {e}" for t, e in errors)

        match stage.on_error:
            case "abort":
                await self.recorder.record_abnormal_exit(
                    work_dir, f"Stage {stage.stage_id} abort: {error_summary}")
                return True  # 终止

            case "skip_task":
                logger.warning("stage_skip_failed_tasks",
                               stage_id=stage.stage_id,
                               skipped=len(errors))
                return False  # 继续

            case "skip_stage":
                logger.warning("stage_skipped",
                               stage_id=stage.stage_id,
                               reason=error_summary)
                return False  # 继续

            case _:
                return False
