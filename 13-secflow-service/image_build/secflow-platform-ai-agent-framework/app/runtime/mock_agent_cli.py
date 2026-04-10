from __future__ import annotations

import json
import re
import sys
from typing import Any, Dict


def _extract_context(prompt: str) -> Dict[str, Any]:
    start = "SECFLOW_CONTEXT_JSON_BEGIN"
    end = "SECFLOW_CONTEXT_JSON_END"
    if start not in prompt or end not in prompt:
        return {}
    raw = prompt.split(start, 1)[1].split(end, 1)[0].strip()
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _phase_from(prompt: str) -> str:
    match = re.search(r"SECFLOW_PHASE:\s*([a-zA-Z0-9_]+)", prompt)
    if match:
        return match.group(1)
    return "worker"


def _respond(prompt: str) -> str:
    phase = _phase_from(prompt)
    context = _extract_context(prompt)
    task_title = context.get("task_title", "Untitled task")
    output_task_type = context.get("output_task_type", "generated_task")
    force_feedback_loop = "REQUIRE_FEEDBACK_LOOP" in prompt
    has_feedback = bool(context.get("failed_feedback_json_path"))

    if phase == "summary":
        payload = {
            "summary_markdown": f"# Summary\n\nTask `{task_title}` completed by mock agent.\n",
            "summary_json": {
                "task_status": "completed",
                "next_stage_hints": [f"produce:{output_task_type}"],
            },
            "results": [
                {
                    "result_id": f"{context.get('task_id', 'task')}-result-001",
                    "title": f"{task_title} finding",
                    "markdown": f"# Result\n\nMock finding for `{task_title}`.\n",
                    "json": {
                        "severity": "high",
                        "summary": f"Mock finding for {task_title}",
                        "next_task_title": f"{task_title} -> {output_task_type}",
                    },
                    "metadata": {
                        "confidence": "mock",
                    },
                }
            ],
        }
        return json.dumps(payload, ensure_ascii=False)

    if phase in {"global_review", "result_review"}:
        if force_feedback_loop and not has_feedback:
            payload = {
                "report_markdown": f"# Review\n\n`{phase}` requires another loop for `{task_title}`.\n",
                "decision": "fail",
                "blocking_issues": [f"{phase} requested another round"],
                "feedback_to_worker": [f"Please revisit {task_title} using the reviewer feedback."],
                "needs_rerun_next_round": True,
            }
            return json.dumps(payload, ensure_ascii=False)
        payload = {
            "report_markdown": f"# Review\n\n`{phase}` passed for `{task_title}`.\n",
            "decision": "pass",
            "blocking_issues": [],
            "feedback_to_worker": [],
            "needs_rerun_next_round": phase == "global_review",
        }
        return json.dumps(payload, ensure_ascii=False)

    if phase == "next_task_generator":
        task_count = 0 if output_task_type == "verified_vuln" else 1
        tasks = []
        for index in range(task_count):
            tasks.append(
                {
                    "title": f"{task_title} -> next-{index + 1}",
                    "body_markdown": f"# Next Task\n\nHandle `{task_title}` as `{output_task_type}`.\n",
                    "metadata": {"generated_by": "mock_agent"},
                }
            )
        return json.dumps({"tasks": tasks}, ensure_ascii=False)

    if phase == "reflection":
        return f"Reflection completed for {task_title}."

    return f"Worker completed task: {task_title}"


def main() -> int:
    if len(sys.argv) > 1:
        sys.stdout.write(_respond(" ".join(sys.argv[1:])))
        return 0

    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line:
            continue
        sys.stdout.write(_respond(line) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
