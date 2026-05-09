"""Stage 3: gate the matched-skill executor."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def run(payload: dict[str, Any], nodes: dict[str, Any] | None = None) -> None:
    feature_file = Path(payload["feature_match_output_file"])
    print(f"AGENTFLOW_PROGRESS stage=skill_gate event=start feature_file={feature_file}", flush=True)
    try:
        data = json.loads(feature_file.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"AGENTFLOW_PROGRESS stage=skill_gate event=error error={exc}", flush=True)
        print(f"AGENTFLOW_SKILL_GATE matched=false reason=FEATURE_MATCH_UNREADABLE error={exc}")
        return

    matched = data.get("matched_skill")
    if matched:
        print(
            f"AGENTFLOW_PROGRESS stage=skill_gate event=finish "
            f"matched=true score={data.get('matched_skill_score')}",
            flush=True,
        )
        print(f"AGENTFLOW_SKILL_GATE matched=true skill={matched}")
    else:
        reason = data.get("matched_status") or "SKIPPED_NO_SKILL"
        print(f"AGENTFLOW_PROGRESS stage=skill_gate event=finish matched=false reason={reason}", flush=True)
        print(f"AGENTFLOW_SKILL_GATE matched=false reason={reason}")

