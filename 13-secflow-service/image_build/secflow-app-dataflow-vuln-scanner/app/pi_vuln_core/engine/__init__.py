"""engine 包导出"""
from app.pi_vuln_core.engine.models import (
    AtomicWorkflowState, AtomicWorkflowResult,
    CompositeWorkflowResult, WorkflowContext, TaskItem,
)

__all__ = [
    "AtomicWorkflowState", "AtomicWorkflowResult",
    "CompositeWorkflowResult", "WorkflowContext", "TaskItem",
    "AtomicWorkflowEngine", "CompositeWorkflowEngine",
    "WorkflowRegistry", "WorkerExecutor",
]


def __getattr__(name: str):
    """Lazy-load executors to keep small submodule imports cycle-free."""
    if name == "AtomicWorkflowEngine":
        from app.pi_vuln_core.engine.atomic import AtomicWorkflowEngine

        return AtomicWorkflowEngine
    if name in {"CompositeWorkflowEngine", "WorkflowRegistry"}:
        from app.pi_vuln_core.engine.composite import CompositeWorkflowEngine, WorkflowRegistry

        return {
            "CompositeWorkflowEngine": CompositeWorkflowEngine,
            "WorkflowRegistry": WorkflowRegistry,
        }[name]
    if name == "WorkerExecutor":
        from app.pi_vuln_core.engine.worker import WorkerExecutor

        return WorkerExecutor
    raise AttributeError(name)
