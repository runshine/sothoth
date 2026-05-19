"""内置插件: 最终产出收集器

将 summary.md 和 results/ 集中复制到 final_output/ 目录，
提供一个干净的、只包含最终结论的输出目录。
"""

import os
import shutil
from app.pi_vuln_core.plugins.base import BasePlugin, PluginContext, PluginResult, PluginResultCode
from app.pi_vuln_core.utils.file_ops import write_json
from app.pi_vuln_core.utils.result_docs import (
    list_supporting_markdown_files,
    result_relations_manifest_path,
    sync_result_relations_manifest,
)
from app.pi_vuln_core.utils.vulnerability_list import (
    STATUS_CONFIRMED,
    STATUS_PENDING,
    entries_by_result_file,
    files_by_status,
    load_vulnerability_list,
    status_counts,
    vulnerability_list_path,
)
from app.pi_vuln_core.utils.logger import get_logger
from app.pi_vuln_core.utils.win_compat import safe_rmtree

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
        result_selection = sync_result_relations_manifest(
            working_dir=ctx.working_dir,
            results_dir=results_dir,
            summary_file=summary_src,
        )
        vuln_payload = load_vulnerability_list(ctx.working_dir)
        vuln_entries = entries_by_result_file(vuln_payload)
        confirmed_files = files_by_status(vuln_payload, STATUS_CONFIRMED)
        pending_files = files_by_status(vuln_payload, STATUS_PENDING)
        if vuln_entries:
            taskable_files = sorted(dict.fromkeys([*confirmed_files, *pending_files]))
        else:
            taskable_files = []
        if not vuln_entries:
            confirmed_files = list(result_selection.get("taskable_results", []))
            taskable_files = list(confirmed_files)
        if os.path.isdir(results_dir):
            final_results_dir = os.path.join(final_dir, "results")
            os.makedirs(final_results_dir, exist_ok=True)
            for f in taskable_files:
                src = os.path.join(results_dir, f)
                if not os.path.isfile(src):
                    continue
                dst = os.path.join(final_results_dir, f)
                shutil.copy2(src, dst)
                collected.append(f"results/{f}")

            false_positive_files = files_by_status(vuln_payload, "false_positive", active_only=False)
            if false_positive_files:
                final_fp_dir = os.path.join(final_dir, "false_positive_results")
                os.makedirs(final_fp_dir, exist_ok=True)
                for f in false_positive_files:
                    src = os.path.join(results_dir, f)
                    if os.path.isfile(src):
                        shutil.copy2(src, os.path.join(final_fp_dir, f))
                        collected.append(f"false_positive_results/{f}")

            supplemental_results = list(result_selection.get("supplemental_results", []))
            if supplemental_results:
                final_supplement_dir = os.path.join(final_dir, "result_supplements")
                os.makedirs(final_supplement_dir, exist_ok=True)
                for f in supplemental_results:
                    src = os.path.join(results_dir, f)
                    dst = os.path.join(final_supplement_dir, f)
                    shutil.copy2(src, dst)
                    collected.append(f"result_supplements/{f}")

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
                safe_rmtree(final_removed_dir)
            shutil.copytree(removed_results_dir, final_removed_dir)
            for root, _, files in os.walk(final_removed_dir):
                rel_root = os.path.relpath(root, final_dir)
                for name in sorted(files):
                    collected.append(os.path.join(rel_root, name))

        # 5. 复制结果关系 manifest / 漏洞状态列表
        manifest_src = result_relations_manifest_path(ctx.working_dir)
        if os.path.isfile(manifest_src):
            manifest_dst = os.path.join(final_dir, "result_relations_manifest.json")
            shutil.copy2(manifest_src, manifest_dst)
            collected.append("result_relations_manifest.json")
        vuln_list_src = vulnerability_list_path(ctx.working_dir)
        if os.path.isfile(vuln_list_src):
            vuln_list_dst = os.path.join(final_dir, "vulnerability_list.json")
            shutil.copy2(vuln_list_src, vuln_list_dst)
            collected.append("vulnerability_list.json")

        # 6. 写入索引
        write_json(os.path.join(final_dir, "index.json"), {
            "description": "最终漏洞挖掘产出",
            "files": collected,
            "result_selection": {
                "all_results": result_selection.get("all_results", []),
                "final_results": result_selection.get("final_results", []),
                "taskable_results": taskable_files,
                "supplemental_results": result_selection.get("supplemental_results", []),
                "excluded_results": result_selection.get("excluded_results", []),
                "selection_source": result_selection.get("selection_source", "all_result_files"),
            },
            "vulnerability_status": {
                "counts": status_counts(vuln_payload),
                "confirmed_files": confirmed_files,
                "false_positive_files": files_by_status(vuln_payload, "false_positive", active_only=False),
                "pending_review_files": files_by_status(vuln_payload, "pending_review"),
            },
        })

        return PluginResult(
            code=PluginResultCode.OK_NEXT,
            message=f"收集 {len(collected)} 个最终产出到 {subdir}/",
            data={"final_output_dir": final_dir, "files": collected},
        )
