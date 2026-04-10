from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from app.artifacts.io import abs_path, ensure_dir, read_json, sanitize_name, write_json, write_text
from app.engine.prompting import build_json_phase_prompt, extract_json_payload, render_prompt
from app.models.contracts import NextTaskDraft, PluginResult, PluginStatus, TaskItem
from app.plugins.base import BasePlugin, PluginExecutionContext


class NoopPlugin(BasePlugin):
    def execute(self, ctx: PluginExecutionContext) -> PluginResult:
        return PluginResult(status=PluginStatus.SUCCESS_NEXT, message="noop")


class NextTaskGeneratorPlugin(BasePlugin):
    def execute(self, ctx: PluginExecutionContext) -> PluginResult:
        generator = ctx.framework_config.run.next_task_generator
        summary_payload = read_json(ctx.summary_json_path) if ctx.summary_json_path else {}
        results_manifest = read_json(ctx.results_manifest_path) if ctx.results_manifest_path else {"items": []}
        prompt_context = {
            "task_id": ctx.task.task_id,
            "task_title": ctx.task.title,
            "task_type": ctx.task.task_type,
            "output_task_type": ctx.workflow_config.output_task_type,
            "summary_json": summary_payload,
            "results_manifest": results_manifest,
            "round_no": ctx.round_no,
        }
        system_prompt = render_prompt(
            ctx.framework_config.prompts[generator.system_prompt_ref],
            prompt_context,
        )
        user_prompt = render_prompt(
            ctx.framework_config.prompts[generator.user_prompt_ref],
            prompt_context,
        )
        prompt = build_json_phase_prompt(
            phase="next_task_generator",
            user_prompt=user_prompt,
            context=prompt_context,
            schema_hint={
                "tasks": [
                    {
                        "title": "string",
                        "body_markdown": "string",
                        "metadata": {},
                    }
                ]
            },
            system_prompt=system_prompt,
        )
        response = ctx.runtime_manager.run_prompt(
            agent_instance_id=generator.agent_instance_id,
            prompt=prompt,
            task_scope=f"{ctx.workflow_config.id}:{ctx.task.task_id}:next-task-generator",
            force_new_session=True,
        )
        if not response.success:
            return PluginResult(status=PluginStatus.FAIL_EXIT_WORKFLOW, message=response.error)
        payload = extract_json_payload(response.output)
        raw_tasks = payload.get("tasks", [])
        drafts = [NextTaskDraft.model_validate(item) for item in raw_tasks]
        if not drafts and not generator.allow_empty:
            return PluginResult(status=PluginStatus.FAIL_EXIT_WORKFLOW, message="next task generator returned no tasks")

        next_tasks_dir = ensure_dir(ctx.task_dir / "next_tasks")
        task_items: List[TaskItem] = []
        for index, draft in enumerate(drafts, start=1):
            task_id = f"{ctx.task.task_id}-next-{index:03d}"
            file_name = f"{sanitize_name(task_id)}.md"
            md_path = write_text(next_tasks_dir / file_name, draft.body_markdown)
            task_items.append(
                TaskItem(
                    task_id=task_id,
                    task_type=ctx.workflow_config.output_task_type,
                    title=draft.title,
                    task_md_path=abs_path(md_path),
                    metadata=draft.metadata,
                    upstream_refs=[ctx.task.task_id],
                )
            )

        manifest_path = write_json(
            next_tasks_dir / "manifest.json",
            {
                "tasks": [item.model_dump(mode="json") for item in task_items],
            },
        )
        ctx.next_task_manifest_path = manifest_path
        return PluginResult(
            status=PluginStatus.SUCCESS_NEXT,
            message=f"generated {len(task_items)} next tasks",
            payload={"task_count": len(task_items), "manifest_path": abs_path(manifest_path)},
        )


BUILTIN_PLUGINS = {
    "builtin.noop": NoopPlugin,
    "builtin.next_task_generator": NextTaskGeneratorPlugin,
}
