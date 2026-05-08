#!/usr/bin/env python3
"""Create a candidate unpacking skill from an archived AgentFlow run."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "app") not in sys.path:
    sys.path.insert(0, str(ROOT / "app"))

from app.skill_store import save_candidate_skill


def _infer_run_id(run_dir: Path) -> str:
    run_id_file = run_dir / "agentflow_run_id.txt"
    if run_id_file.exists():
        value = run_id_file.read_text(encoding="utf-8").strip()
        if value:
            return value
    final_result = run_dir / "final_result.json"
    if final_result.exists():
        try:
            payload = json.loads(final_result.read_text(encoding="utf-8"))
            value = str(payload.get("agentflow_run_id") or "").strip()
            if value:
                return value
        except Exception:
            pass
    return run_dir.name


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True, help="Task run directory containing final_result.json and AgentFlow artifacts.")
    parser.add_argument("--node-id", default="generic_executor", help="Source node id for traceability.")
    parser.add_argument("--skill-document", required=True, help="Markdown skill document to save as a candidate.")
    parser.add_argument("--skills-dir", required=True, help="Skill repository directory.")
    parser.add_argument("--family-id", default="", help="Fallback family id if the document omits one.")
    parser.add_argument("--evaluation-batch", default="", help="Optional offline evaluation batch id.")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    raw_document = Path(args.skill_document).read_text(encoding="utf-8")
    saved = save_candidate_skill(
        Path(args.skills_dir),
        raw_document,
        {
            "family_id": args.family_id or run_dir.name,
            "source_run_id": _infer_run_id(run_dir),
            "source_node_id": args.node_id,
            "evaluation_batch": args.evaluation_batch,
        },
    )
    print(json.dumps(saved, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
