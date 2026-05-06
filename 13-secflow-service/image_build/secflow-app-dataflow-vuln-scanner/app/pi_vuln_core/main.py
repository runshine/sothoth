"""
框架入口点

Docker 容器 / K8S JOB 的启动入口

命令行选项:
  --config, -c         JSON 配置文件路径 (必须)
  --keep-workspace     执行完毕后保留工作目录 (默认)
  --clean-workspace    执行完毕后删除工作目录 (生产模式)
"""

from __future__ import annotations

import asyncio
import argparse
import sys
import os

from app.pi_vuln_core.config.loader import ConfigLoader, ConfigValidationError
from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.plugins.registry import PluginRegistry
from app.pi_vuln_core.plugins.executor import PluginChainExecutor
from app.pi_vuln_core.workspace.manager import WorkspaceManager
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.engine.composite import CompositeWorkflowEngine
from app.pi_vuln_core.utils.logger import (
    setup_logging, get_logger, attach_log_file, detach_log_file,
)
from app.pi_vuln_core.utils.file_ops import write_json
from app.pi_vuln_core.utils.win_compat import ensure_event_loop_policy, safe_rmtree


async def main(config_path: str, clean_workspace: bool = False) -> int:
    """
    主入口

    Args:
        config_path:       JSON 配置文件路径
        clean_workspace:   执行完毕后是否删除工作目录

    Returns:
        退出码 (0=成功, 1=失败)
    """
    logger = get_logger("main")
    workspace_root = None
    agent_registry = None
    interrupted = False

    try:
        # 1. 加载并校验 JSON 配置
        logger.info("loading_configuration", path=config_path)
        config = ConfigLoader.load(config_path)

        # 2. 初始化日志
        setup_logging(config.global_config.log_level)
        logger = get_logger("main")

        # 3. 设置全局环境变量
        for key, value in config.global_config.env_vars.items():
            os.environ.setdefault(key, value)

        workspace_root = config.global_config.workspace_root

        # 4. 初始化智能体注册表
        logger.info("initializing_agents", count=len(config.agents))
        agent_registry = AgentRuntimeRegistry()
        agent_registry.register_from_config(
            [a.model_dump() for a in config.agents])
        await agent_registry.initialize_all()

        # 5. 初始化插件注册表
        logger.info("initializing_plugins", count=len(config.plugins))
        plugin_registry = PluginRegistry()
        plugin_registry.register_from_config(
            [p.model_dump() for p in config.plugins])

        # 6. 初始化基础设施
        workspace = WorkspaceManager(workspace_root)
        recorder = ExecutionRecorder(workspace_root)
        plugin_executor = PluginChainExecutor(plugin_registry)

        # 7. 创建组合工作流引擎
        engine = CompositeWorkflowEngine(
            config=config,
            agent_registry=agent_registry,
            plugin_executor=plugin_executor,
            workspace=workspace,
            recorder=recorder,
        )

        # 8. 验证入口配置 (R11)
        exec_cfg = config.execution
        assert exec_cfg.entry_workflow_type == "composite", \
            "入口工作流必须是组合工作流 (R11)"

        # 9. 确保输入文件存在
        if not os.path.exists(exec_cfg.input_task.task_file):
            logger.error("input_task_not_found",
                         path=exec_cfg.input_task.task_file)
            return exec_cfg.on_completion.exit_code_on_failure

        # 10. 确保输出目录存在
        os.makedirs(exec_cfg.output_dir, exist_ok=True)

        logger.info("starting_workflow",
                     entry=exec_cfg.entry_workflow,
                     execution_id=exec_cfg.execution_id,
                     input_task=exec_cfg.input_task.task_file,
                     keep_workspace=not clean_workspace)

        # 11. 执行
        result = await engine.run(
            workflow_id=exec_cfg.entry_workflow,
            input_task_file=exec_cfg.input_task.task_file,
            execution_id=exec_cfg.execution_id,
        )

        # 12. 写入执行总结
        if exec_cfg.on_completion.write_summary:
            summary_file = exec_cfg.on_completion.summary_file
            write_json(summary_file, result.to_dict())
            logger.info("summary_written", path=summary_file)

        # 13. 退出码 (R14)
        if result.success:
            logger.info("workflow_completed_successfully",
                         final_tasks=len(result.final_tasks),
                         workspace=workspace_root)
            return exec_cfg.on_completion.exit_code_on_success
        else:
            logger.error("workflow_failed", error=result.error)
            return exec_cfg.on_completion.exit_code_on_failure

    except ConfigValidationError as e:
        logger.error("config_validation_failed", errors=e.errors)
        return 1

    except (KeyboardInterrupt, asyncio.CancelledError) as e:
        interrupted = True
        logger.warning("workflow_interrupted", error=type(e).__name__)
        return 130

    except Exception as e:
        logger.error("unexpected_error", error=str(e), exc_info=True)
        return 1

    finally:
        # 关闭 Agent 运行时
        if agent_registry:
            try:
                await agent_registry.shutdown_all()
            except Exception:
                pass

        # 清理工作目录
        if clean_workspace and not interrupted and workspace_root and os.path.isdir(workspace_root):
            logger.info("cleaning_workspace", path=workspace_root)
            safe_rmtree(workspace_root, ignore_errors=True)
        elif workspace_root:
            logger.info("workspace_preserved", path=workspace_root)


def cli_entry() -> None:
    """CLI 入口点"""
    parser = argparse.ArgumentParser(
        description="多智能体协同工作流框架",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 正常运行 (默认保留工作目录，便于调试)
  python -m src.main -c config/workflow.json

  # 生产模式 (执行后清理中间文件)
  python -m src.main -c config/workflow.json --clean-workspace

  # 运行后检查中间产物
  ls /workspace/pipeline_*/stage_*/task_*/reviews/
""")

    parser.add_argument(
        "--config", "-c",
        required=True,
        help="JSON 配置文件路径")

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--keep-workspace",
        action="store_true",
        default=True,
        help="执行完毕后保留工作目录 (默认行为，便于调试和调优)")
    group.add_argument(
        "--clean-workspace",
        action="store_true",
        default=False,
        help="执行完毕后删除工作目录 (生产模式，节省磁盘)")

    parser.add_argument(
        "--log-file",
        default=None,
        help="同时将所有 stdout/stderr 输出记录到指定日志文件")

    args = parser.parse_args()

    # 启动日志文件记录
    if args.log_file:
        actual_log = attach_log_file(args.log_file)
        print(f"  日志文件: {actual_log}")

    # 初始化基础日志
    setup_logging("INFO")
    ensure_event_loop_policy()

    exit_code = asyncio.run(main(args.config,
                                  clean_workspace=args.clean_workspace))

    # 停止日志文件记录
    if args.log_file:
        detach_log_file()

    sys.exit(exit_code)


if __name__ == "__main__":
    cli_entry()
