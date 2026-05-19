"""内置插件: 下阶段任务生成器 (R6i, R13)"""

import os
from app.pi_vuln_core.plugins.base import BasePlugin, PluginContext, PluginResult, PluginResultCode
from app.pi_vuln_core.utils.file_ops import read_file, write_file, write_json
from app.pi_vuln_core.utils.result_docs import sync_result_relations_manifest
from app.pi_vuln_core.utils.vulnerability_list import (
    STATUS_CONFIRMED,
    STATUS_PENDING,
    entries_by_result_file,
    files_by_status,
    load_vulnerability_list,
)
from app.pi_vuln_core.utils.template import render_template
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("plugin.next_task_gen")


class NextTaskGeneratorPlugin(BasePlugin):
    """
    使用软件代码 + AI Agent 生成下一阶段任务清单

    配置项:
    - agent_id:         用于生成任务的智能体 ID
    - prompt_template:  prompt 模板文件路径
    - output_subdir:    输出子目录名 (默认 "output")
    """

    @property
    def plugin_id(self) -> str:
        return "next_task_generator"

    async def execute(self, ctx: PluginContext) -> PluginResult:
        agent_id = ctx.plugin_config.get("agent_id")
        prompt_tpl = ctx.plugin_config.get("prompt_template")
        output_subdir = ctx.plugin_config.get("output_subdir", "output")

        output_dir = os.path.join(ctx.working_dir, output_subdir)
        os.makedirs(output_dir, exist_ok=True)

        # 读取当前任务的结果
        summary_content = ""
        if ctx.summary_file and os.path.exists(ctx.summary_file):
            summary_content = read_file(ctx.summary_file)

        result_selection = {
            "all_results": [],
            "final_results": [],
            "taskable_results": [],
            "supplemental_results": [],
            "excluded_results": [],
            "selection_source": "all_result_files",
        }
        results_list = []
        if ctx.results_dir and os.path.isdir(ctx.results_dir):
            result_selection = sync_result_relations_manifest(
                working_dir=ctx.working_dir,
                results_dir=ctx.results_dir,
                summary_file=ctx.summary_file,
            )
            vuln_payload = load_vulnerability_list(ctx.working_dir)
            vuln_entries = entries_by_result_file(vuln_payload)
            confirmed = files_by_status(vuln_payload, STATUS_CONFIRMED)
            pending = files_by_status(vuln_payload, STATUS_PENDING)
            if vuln_entries:
                results_list = sorted(dict.fromkeys([*confirmed, *pending]))
            else:
                results_list = list(result_selection.get("taskable_results", []))

        # 如果有配置 agent_id + prompt，使用 AI 生成
        if agent_id and prompt_tpl and ctx.agent_registry:
            try:
                agent = ctx.agent_registry.get(agent_id)
                prompt = render_template(
                    prompt_tpl,
                    summary=summary_content,
                    results="\n".join(results_list),
                    results_dir=ctx.results_dir or "",
                    working_dir=ctx.working_dir,
                )

                response = await agent.send_message(
                    message=prompt,
                    working_dir=ctx.working_dir,
                )

                if response.success:
                    logger.info("ai_task_generation_done",
                                content_len=len(response.content))
            except Exception as e:
                logger.warning("ai_task_generation_failed", error=str(e))

        # 软件逻辑：扫描 results/ 下的每个 MD 文件作为独立任务
        task_files = []
        if ctx.results_dir and os.path.isdir(ctx.results_dir):
            for result_file in results_list:
                src_path = os.path.join(ctx.results_dir, result_file)
                dst_path = os.path.join(output_dir, f"task_{result_file}")
                # 复制结果文件作为下一阶段任务输入
                content = read_file(src_path)
                write_file(dst_path, content)
                task_files.append({
                    "id": os.path.splitext(result_file)[0],
                    "file": dst_path,
                })

        # 写入任务索引
        if task_files:
            write_json(
                os.path.join(output_dir, "next_tasks.json"),
                {
                    "tasks": task_files,
                    "result_selection": {
                        "taskable_results": results_list,
                        "supplemental_results": result_selection.get("supplemental_results", []),
                        "excluded_results": result_selection.get("excluded_results", []),
                        "selection_source": result_selection.get("selection_source", "all_result_files"),
                    },
                })

        return PluginResult(
            code=PluginResultCode.OK_NEXT,
            message=f"生成 {len(task_files)} 个下阶段任务",
            data={"next_task_count": len(task_files),
                  "task_files": [t["file"] for t in task_files]},
        )
