"""内置插件: 最终产出收集器

将 summary.md 和 results/ 集中复制到 final_output/ 目录，
提供一个干净的、只包含最终结论的输出目录。
"""

import os
import shutil
from app.pi_vuln_core.plugins.base import BasePlugin, PluginContext, PluginResult, PluginResultCode
from app.pi_vuln_core.utils.file_ops import write_json
from app.pi_vuln_core.utils.result_docs import list_result_report_files, list_supporting_markdown_files
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("plugin.final_output")


class FinalOutputCollectorPlugin(BasePlugin):
    """
    收集最终产出到 final_output/ 目录

    配置项:
    - output_subdir: 输出子目录名 (默认 "final_output")
    """

    @property
    def plugin_id(self) -> str:
        return "final_output_collector"

    async def execute(self, ctx: PluginContext) -> PluginResult:
        subdir = ctx.plugin_config.get("output_subdir", "final_output")
        final_dir = os.path.join(ctx.working_dir, subdir)
        os.makedirs(final_dir, exist_ok=True)

        collected = []

        # 1. 复制 summary.md
        summary_src = ctx.summary_file
        if not summary_src:
            summary_src = os.path.join(ctx.working_dir, "summary.md")
        if os.path.isfile(summary_src):
            dst = os.path.join(final_dir, "summary.md")
            shutil.copy2(summary_src, dst)
            collected.append("summary.md")

        # 2. 复制 results/ 下的所有 result_*.md
        results_dir = ctx.results_dir
        if not results_dir:
            results_dir = os.path.join(ctx.working_dir, "results")
        if os.path.isdir(results_dir):
            final_results_dir = os.path.join(final_dir, "results")
            os.makedirs(final_results_dir, exist_ok=True)
            for f in list_result_report_files(results_dir):
                src = os.path.join(results_dir, f)
                dst = os.path.join(final_results_dir, f)
                shutil.copy2(src, dst)
                collected.append(f"results/{f}")

        # 3. 复制 supporting_docs/（若有）
        supporting_docs_dir = os.path.join(ctx.working_dir, "supporting_docs")
        if os.path.isdir(supporting_docs_dir):
            final_supporting_dir = os.path.join(final_dir, "supporting_docs")
            os.makedirs(final_supporting_dir, exist_ok=True)
            for f in list_supporting_markdown_files(supporting_docs_dir):
                src = os.path.join(supporting_docs_dir, f)
                dst = os.path.join(final_supporting_dir, f)
                shutil.copy2(src, dst)
                collected.append(f"supporting_docs/{f}")

        # 4. 复制被删除/淘汰的漏洞报告备份（若有）
        removed_results_dir = os.path.join(ctx.working_dir, "removed_results")
        if os.path.isdir(removed_results_dir):
            final_removed_dir = os.path.join(final_dir, "removed_results")
            if os.path.isdir(final_removed_dir):
                shutil.rmtree(final_removed_dir)
            shutil.copytree(removed_results_dir, final_removed_dir)
            for root, _, files in os.walk(final_removed_dir):
                rel_root = os.path.relpath(root, final_dir)
                for name in sorted(files):
                    collected.append(os.path.join(rel_root, name))

        # 5. 写入索引
        write_json(os.path.join(final_dir, "index.json"), {
            "description": "最终漏洞挖掘产出",
            "files": collected,
        })

        return PluginResult(
            code=PluginResultCode.OK_NEXT,
            message=f"收集 {len(collected)} 个最终产出到 {subdir}/",
            data={"final_output_dir": final_dir, "files": collected},
        )
