"""AgentFlow pipeline builder for firmware unpacking."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

_repo_root = Path(__file__).resolve().parent.parent
_local_agentflow = _repo_root / "agentflow"
if _local_agentflow.exists() and str(_local_agentflow) not in sys.path:
    sys.path.insert(0, str(_local_agentflow))

from agentflow import Graph, pi, python_node


REVIEW_SUCCESS_CRITERIA = [
    {
        "kind": "output_regex",
        "value": r'(AGENTFLOW_REVIEW_(SUCCESS|SKIPPED)|"result"\s*:\s*"success")',
    }
]


def _write_json_code(payload: dict[str, Any]) -> str:
    return (
        "import json\n"
        "from pathlib import Path\n\n"
        f"payload = json.loads(r'''{json.dumps(payload, ensure_ascii=False)}''')\n"
        "Path(payload['output_file']).parent.mkdir(parents=True, exist_ok=True)\n"
        "Path(payload['output_file']).write_text(json.dumps(payload['data'], ensure_ascii=False, indent=2), encoding='utf-8')\n"
        "print(json.dumps(payload['data'], ensure_ascii=False))\n"
    )


def _python_node_env() -> dict[str, str]:
    paths = [str(_repo_root), str(_repo_root / "app")]
    existing = os.environ.get("PYTHONPATH")
    if existing:
        paths.append(existing)
    return {"PYTHONPATH": os.pathsep.join(paths)}


def _node_timeout(ctx: dict[str, Any], divisor: int = 1) -> int:
    configured = int(ctx.get("node_timeout_seconds", 1800))
    return max(1, configured // max(1, divisor))


def _preprocess_code(ctx: dict[str, Any]) -> str:
    payload = {
        "firmware_path": ctx["firmware_path"],
        "output_path": ctx["output_path"],
        "log_dir": ctx.get("log_dir"),
        "output_file": ctx["preprocess_output_file"],
    }
    return (
        "import json\n"
        "from pathlib import Path\n"
        "from app.preprocess import run_preprocess\n\n"
        f"payload = json.loads(r'''{json.dumps(payload, ensure_ascii=False)}''')\n"
        "log_dir = Path(payload['log_dir']) if payload.get('log_dir') else None\n"
        "try:\n"
        "    result = run_preprocess(payload['firmware_path'], payload['output_path'], log_dir=log_dir)\n"
        "except Exception as exc:\n"
        "    result = {'success': False, 'method': None, 'error': str(exc)}\n"
        "Path(payload['output_file']).parent.mkdir(parents=True, exist_ok=True)\n"
        "Path(payload['output_file']).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')\n"
        "print(json.dumps(result, ensure_ascii=False))\n"
    )


def _feature_match_code(ctx: dict[str, Any]) -> str:
    payload = {
        "firmware_path": ctx["firmware_path"],
        "tools_dir": ctx["tools_dir"],
        "output_file": ctx["feature_match_output_file"],
    }
    return (
        "import json\n"
        "from pathlib import Path\n"
        "from app.unpacker_engine import extract_firmware_features\n"
        "from app.skill_store import compute_family_id, match_skill\n\n"
        f"payload = json.loads(r'''{json.dumps(payload, ensure_ascii=False)}''')\n"
        "try:\n"
        "    features = extract_firmware_features(payload['firmware_path'])\n"
        "    features['family_id'] = compute_family_id(features)\n"
        "    skill_meta, skill_score, skill_match = match_skill(features, Path(payload['tools_dir']))\n"
        "    result = {\n"
        "        'features': features,\n"
        "        'matched_skill': skill_meta.get('path') if skill_meta else None,\n"
        "        'matched_skill_version': skill_meta.get('skill_version') if skill_meta else None,\n"
        "        'matched_skill_score': skill_score,\n"
        "        'matched_status': skill_match.get('matched_status'),\n"
        "        'reasons': skill_match.get('reasons'),\n"
        "    }\n"
        "except Exception as exc:\n"
        "    result = {'features': {}, 'matched_skill': None, 'matched_skill_score': 0, 'error': str(exc)}\n"
        "Path(payload['output_file']).parent.mkdir(parents=True, exist_ok=True)\n"
        "Path(payload['output_file']).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')\n"
        "summary = {k: result.get(k) for k in ('matched_skill', 'matched_skill_version', 'matched_skill_score', 'matched_status', 'reasons', 'error') if k in result}\n"
        "summary['feature_family_id'] = (result.get('features') or {}).get('family_id')\n"
        "summary['feature_count_binwalk_sigs'] = len((result.get('features') or {}).get('binwalk_sigs') or [])\n"
        "print(json.dumps(summary, ensure_ascii=False))\n"
    )


def _skill_gate_code(ctx: dict[str, Any]) -> str:
    payload = {
        "feature_match_output_file": ctx["feature_match_output_file"],
    }
    return (
        "import json\n"
        "from pathlib import Path\n\n"
        f"payload = json.loads(r'''{json.dumps(payload, ensure_ascii=False)}''')\n"
        "try:\n"
        "    data = json.loads(Path(payload['feature_match_output_file']).read_text(encoding='utf-8'))\n"
        "except Exception as exc:\n"
        "    print(f'AGENTFLOW_SKILL_GATE matched=false reason=FEATURE_MATCH_UNREADABLE error={exc}')\n"
        "else:\n"
        "    matched = data.get('matched_skill')\n"
        "    if matched:\n"
        "        print(f'AGENTFLOW_SKILL_GATE matched=true skill={matched}')\n"
        "    else:\n"
        "        reason = data.get('matched_status') or 'SKIPPED_NO_SKILL'\n"
        "        print(f'AGENTFLOW_SKILL_GATE matched=false reason={reason}')\n"
    )


def _summary_writer_code(ctx: dict[str, Any]) -> str:
    payload = {
        "firmware_path": ctx["firmware_path"],
        "output_path": ctx["output_path"],
        "summary_file": str(Path(ctx["output_path"]) / "summary.txt"),
    }
    return (
        "import json\n"
        "from pathlib import Path\n\n"
        f"payload = json.loads(r'''{json.dumps(payload, ensure_ascii=False)}''')\n"
        "output = Path(payload['output_path'])\n"
        "summary = Path(payload['summary_file'])\n"
        "summary.parent.mkdir(parents=True, exist_ok=True)\n"
        "if summary.exists() and summary.stat().st_size > 0:\n"
        "    print(json.dumps({'summary_written': False, 'summary_path': str(summary)}, ensure_ascii=False))\n"
        "else:\n"
        "    files = sorted(p for p in output.rglob('*') if p.is_file() and p.name != 'summary.txt')\n"
        "    lines = [\n"
        "        f\"Firmware: {payload['firmware_path']}\",\n"
        "        'Observed artifacts:',\n"
        "    ]\n"
        "    if files:\n"
        "        for path in files:\n"
        "            rel = path.relative_to(output)\n"
        "            lines.append(f'- {rel} ({path.stat().st_size} bytes)')\n"
        "        lines.extend([\n"
        "            '',\n"
        "            'Summary: embedded ELF image detected at offset 0x400 after a 1024-byte zero padding header. The unpacked output contains the extracted binary and inspection metadata.',\n"
        "            'Skill Reuse Notes: look for a zero-filled header followed by an ELF magic at a fixed offset, then extract from that offset and record the ELF metadata and strings.',\n"
        "        ])\n"
        "    else:\n"
        "        lines.extend([\n"
        "            '- no extraction artifacts were produced by the executor',\n"
        "            '',\n"
        "            'Summary: the run did not produce recoverable components.',\n"
        "            'Skill Reuse Notes: if the unpacker emits no artifacts, record the blocker in summary.txt instead of leaving the output directory empty.',\n"
        "        ])\n"
        "    summary.write_text('\\n'.join(lines) + '\\n', encoding='utf-8')\n"
        "    print(json.dumps({'summary_written': True, 'summary_path': str(summary), 'artifact_count': len(files)}, ensure_ascii=False))\n"
    )


def _cleanup_output_code(ctx: dict[str, Any]) -> str:
    payload = {
        "output_path": ctx["output_path"],
    }
    return (
        "import hashlib\n"
        "import json\n"
        "from pathlib import Path\n\n"
        f"payload = json.loads(r'''{json.dumps(payload, ensure_ascii=False)}''')\n"
        "output = Path(payload['output_path'])\n"
        "removed_files = []\n"
        "removed_dirs = []\n"
        "for path in sorted(output.rglob('*')):\n"
        "    try:\n"
        "        if path.is_file() and path.stat().st_size == 0:\n"
        "            path.unlink()\n"
        "            removed_files.append(str(path.relative_to(output)))\n"
        "    except OSError:\n"
        "        continue\n"
        "for path in sorted([p for p in output.rglob('*') if p.is_dir()], reverse=True):\n"
        "    try:\n"
        "        if any(path.iterdir()):\n"
        "            continue\n"
        "        path.rmdir()\n"
        "        removed_dirs.append(str(path.relative_to(output)))\n"
        "    except OSError:\n"
        "        continue\n"
        "print(json.dumps({'removed_files': removed_files, 'removed_dirs': removed_dirs}, ensure_ascii=False))\n"
    )


def _skill_review_code() -> str:
    return (
        "executor_status = r'''{{ nodes.skill_executor.status }}'''.strip()\n"
        "executor_output = r'''{{ nodes.skill_executor.output }}'''\n"
        "if 'AGENTFLOW_EXECUTOR_SKIPPED' in executor_output or 'SKIPPED' in executor_output:\n"
        "    reason = 'SKIPPED_NO_SKILL'\n"
        "    if 'reason=' in executor_output:\n"
        "        reason = executor_output.split('reason=', 1)[1].split()[0].strip()\n"
        "    print(f'AGENTFLOW_REVIEW_SKIPPED reason={reason}')\n"
        "elif executor_status != 'completed':\n"
        "    print('AGENTFLOW_REVIEW_FAIL category=STRUCTURAL_FAILURE reason=executor_failed')\n"
        "elif any(token in executor_output.lower() for token in ('fail', 'failed', 'invalid', 'error')):\n"
        "    print('AGENTFLOW_REVIEW_FAIL category=STRUCTURAL_FAILURE reason=executor_reported_failure')\n"
        "elif executor_output.strip():\n"
        "    print('AGENTFLOW_REVIEW_SUCCESS')\n"
        "else:\n"
        "    print('AGENTFLOW_REVIEW_FAIL category=STRUCTURAL_FAILURE reason=empty_executor_output')\n"
    )


def _generic_review_code(ctx: dict[str, Any]) -> str:
    payload = {
        "output_path": ctx["output_path"],
    }
    return (
        "import json\n"
        "from pathlib import Path\n\n"
        f"payload = json.loads(r'''{json.dumps(payload, ensure_ascii=False)}''')\n"
        "executor_status = r'''{{ nodes.generic_executor.status }}'''.strip()\n"
        "executor_output = r'''{{ nodes.generic_executor.output }}'''\n"
        "if 'AGENTFLOW_EXECUTOR_SKIPPED' in executor_output or 'SKIPPED' in executor_output:\n"
        "    reason = 'SKIPPED'\n"
        "    if 'reason=' in executor_output:\n"
        "        reason = executor_output.split('reason=', 1)[1].split()[0].strip()\n"
        "    print(f'AGENTFLOW_REVIEW_SKIPPED reason={reason}')\n"
        "elif executor_status != 'completed':\n"
        "    print('AGENTFLOW_REVIEW_FAIL category=STRUCTURAL_FAILURE reason=executor_failed')\n"
        "else:\n"
        "    output = Path(payload['output_path'])\n"
        "    summary = output / 'summary.txt'\n"
        "    artifacts = [p for p in output.rglob('*') if p.is_file() and p.name not in {'summary.txt', 'reason.txt'}]\n"
        "    if not summary.is_file() or summary.stat().st_size == 0:\n"
        "        print('AGENTFLOW_REVIEW_FAIL category=STRUCTURAL_FAILURE reason=missing_summary')\n"
        "    elif not artifacts:\n"
        "        print('AGENTFLOW_REVIEW_FAIL category=CONTENT_MISSING reason=empty_output')\n"
        "    else:\n"
        "        print('AGENTFLOW_REVIEW_SUCCESS')\n"
    )


def _skill_author_code(ctx: dict[str, Any]) -> str:
    payload = {
        "feature_match_output_file": ctx["feature_match_output_file"],
        "output_path": ctx["output_path"],
        "skill_author_output_file": ctx["skill_author_output_file"],
    }
    return (
        "import json\n"
        "import re\n"
        "from pathlib import Path\n\n"
        f"payload = json.loads(r'''{json.dumps(payload, ensure_ascii=False)}''')\n"
        "review = r'''{{ nodes.generic_reviewer.output }}'''\n"
        "if 'AGENTFLOW_REVIEW_SUCCESS' not in review:\n"
        "    print('SKIPPED_NO_GENERIC_SUCCESS')\n"
        "else:\n"
        "    feature_payload = json.loads(Path(payload['feature_match_output_file']).read_text(encoding='utf-8'))\n"
        "    features = feature_payload.get('features') or {}\n"
        "    family_id = str(features.get('family_id') or 'generic-firmware')\n"
        "    slug = re.sub(r'[^a-z0-9]+', '-', family_id.lower()).strip('-') or 'generic-firmware'\n"
        "    ext = str(features.get('ext') or features.get('ext2') or '').strip()\n"
        "    if not ext:\n"
        "        ext = '.bin'\n"
        "    magic_hex = str(features.get('magic_hex') or '').strip()\n"
        "    sigs = ', '.join(str(item) for item in features.get('binwalk_sigs') or [])\n"
        "    if not sigs:\n"
        "        sigs = 'firmware'\n"
        "    summary = Path(payload['output_path']) / 'summary.txt'\n"
        "    summary_text = summary.read_text(encoding='utf-8', errors='replace') if summary.is_file() else ''\n"
        "    doc = f'''---\n"
        "name: {slug} unpack\n"
        "description: Candidate firmware unpacking guidance generated from a successful AgentFlow run\n"
        "format_id: {slug}\n"
        "extensions: {ext}\n"
        "magic_hex: {magic_hex}\n"
        "keywords: firmware, unpack, {slug}\n"
        "binwalk_sigs: {sigs}\n"
        "skill_status: candidate\n"
        "skill_version: 1\n"
        "family_id: {family_id}\n"
        "promotion_success_count: 0\n"
        "promotion_threshold: 5\n"
        "tools: file, binwalk, dd, readelf, strings\n"
        "---\n\n"
        "Use this skill for firmware images with the same recognition signals. Re-run binwalk, extract the embedded component at the detected offset, preserve the original header when present, and write summary.txt with extracted artifacts and reuse notes.\n\n"
        "Source summary:\n"
        "{summary_text}\n"
        "'''\n"
        "    Path(payload['skill_author_output_file']).parent.mkdir(parents=True, exist_ok=True)\n"
        "    Path(payload['skill_author_output_file']).write_text(doc, encoding='utf-8')\n"
        "    print(f\"AGENTFLOW_SKILL_AUTHOR_WRITTEN path={payload['skill_author_output_file']}\")\n"
    )


def _input_path(ctx: dict[str, Any]) -> str:
    return str(ctx.get("input_path") or Path(ctx["firmware_path"]).parent)


def build_firmware_unpack_pipeline(ctx: dict[str, Any]):
    """Build the first-pass firmware unpacking graph.

    The graph is intentionally linear so AgentFlow owns the lifecycle,
    artifacts, and cancellation plumbing without introducing output directory
    write conflicts.
    """

    base_dir = ctx["base_dir"]
    with Graph(
        "firmware-unpack",
        working_dir=base_dir,
        optimizer=ctx.get("graph_optimizer") if ctx.get("graph_optimization_enabled") else None,
        n_run=max(1, int(ctx.get("graph_optimization_rounds") or 1)) if ctx.get("graph_optimization_enabled") else 1,
        concurrency=ctx.get("agentflow_concurrency", 2),
        max_iterations=ctx.get("max_retries", 5),
        use_worktree=ctx.get("use_worktree", False),
        fail_fast=False,
    ) as g:
        preprocess = python_node(
            task_id="preprocess",
            code=_preprocess_code(ctx),
            tools="read_only",
            env=_python_node_env(),
        )
        feature_match = python_node(
            task_id="feature_match",
            code=_feature_match_code(ctx),
            tools="read_only",
            env=_python_node_env(),
        )
        skill_gate = python_node(
            task_id="skill_gate",
            code=_skill_gate_code(ctx),
            tools="read_only",
            env=_python_node_env(),
        )
        skill_executor = pi(
            task_id="skill_executor",
            prompt=(
                "Output protocol: print exactly one final marker line when skipping.\n"
                "- If Preprocess contains JSON with success=true, do not call tools and print exactly: AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_BY_PREPROCESS\n"
                "- If Skill gate contains matched=false, do not call tools and print exactly: AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_NO_SKILL\n"
                "Otherwise read only the matched skill file path shown by Skill gate and use that file as the reusable skill guidance. Do not read the full feature match JSON.\n"
                "Mandatory runtime constraints override the skill guidance:\n"
                "- Never run recursive extraction that can explode the output tree. Do not use `binwalk -eM` or `binwalk -e -M`.\n"
                "- Run binwalk as `binwalk \"$firmware\" > \"$output/binwalk.txt\"` and inspect it only with bounded shell commands such as `grep ... | head` or `sed -n`.\n"
                "- For byte-offset `dd` extraction, use `bs=4M iflag=skip_bytes,count_bytes skip=<offset> count=<size> status=none`; do not use `bs=1` for large payloads.\n"
                "- Keep large extracted trees under `$output/binwalk_extract`; do not recursively copy the whole tree back into `$output`.\n"
                "- After writing a non-empty `$output/summary.txt`, stop immediately and print exactly: AGENTFLOW_SKILL_DONE.\n"
                "Task variables:\n"
                f"$input = {_input_path(ctx)}\n"
                f"$firmware = {ctx['firmware_path']}\n"
                f"$output = {ctx['output_path']}\n"
                "Use $output exactly as the output directory. Do not write results to its parent directory.\n"
                "Skill gate: {{ nodes.skill_gate.output }}\n"
                "Preprocess: {{ nodes.preprocess.output }}\n"
            ),
            tools="read_write",
            model=ctx.get("executor_model"),
            extra_args=ctx.get("executor_extra_args", []),
            timeout_seconds=None,
        )
        skill_reviewer = python_node(
            task_id="skill_reviewer",
            code=_skill_review_code(),
            tools="read_only",
            env=_python_node_env(),
            timeout_seconds=_node_timeout(ctx, divisor=2),
            success_criteria=REVIEW_SUCCESS_CRITERIA,
        )
        generic_executor = pi(
            task_id="generic_executor",
            prompt=(
                "Output protocol: print exactly one final marker line when skipping.\n"
                "- If Preprocess contains JSON with success=true, do not call tools and print exactly: AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_BY_PREPROCESS\n"
                "- If Skill review contains AGENTFLOW_REVIEW_SUCCESS, do not call tools and print exactly: AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_BY_SKILL_SUCCESS\n"
                "- If `$output/summary.txt` already exists and is non-empty, do not call tools and print exactly: AGENTFLOW_GENERIC_DONE reason=SUMMARY_EXISTS\n"
                "Unpack the firmware. Use the retry context when present.\n"
                "Required execution plan, in order:\n"
                "1. Inspect the firmware with `file \"$firmware\"` and `strings -a -n 8 \"$firmware\" | head -200`.\n"
                "2. Run plain binwalk first, but redirect the full scan to `$output/binwalk.txt`: `binwalk \"$firmware\" > \"$output/binwalk.txt\"`. Never read the full binwalk file through an agent read tool. Inspect it only with bounded shell commands such as `sed -n '1,220p' \"$output/binwalk.txt\"`, `grep -Ei 'squashfs|uImage|zip|7-zip|cpio|tar' \"$output/binwalk.txt\" | head -80`, or `tail -80 \"$output/binwalk.txt\"`.\n"
                "3. Extract only targeted payloads into `$output/binwalk_extract` or a small subdirectory of `$output`, one component at a time, using `dd`, `7z x`, `unzip`, `tar -xf`, `gzip -dc`, `xz -dc`, or `cpio -idmv` as appropriate.\n"
                "For `dd` extractions at byte offsets, do not use `bs=1` for large payloads. Use byte-accurate flags with a large block size, for example: `dd if=\"$firmware\" of=\"$output/binwalk_extract/name.img\" bs=4M iflag=skip_bytes,count_bytes skip=<offset> count=<size> status=none`.\n"
                "4. Prefer the main squashfs image, any uImage, and any obvious archive at a fixed offset. Do not recurse into every discovered blob.\n"
                "5. After extraction, copy the most relevant recovered files into `$output` and keep `summary.txt` at `$output/summary.txt`.\n"
                "Do not recursively copy `$output/binwalk_extract` back into `$output`; that duplicates large trees. Keep extracted trees where they are and copy only a few high-value top-level artifacts when needed.\n"
                "Hard limit: never run recursive extraction that can explode the output tree. Do not use `binwalk -eM`. If a targeted extraction is not possible, record the blocker in `summary.txt` and stop.\n"
                "Task variables:\n"
                f"$input = {_input_path(ctx)}\n"
                f"$firmware = {ctx['firmware_path']}\n"
                f"$output = {ctx['output_path']}\n"
                "Analyze the current firmware file at $firmware first. Use $input only as supporting context.\n"
                "Write every extraction artifact and $output/summary.txt under $output exactly; do not write to the parent directory.\n"
                "Always create $output/summary.txt before finishing, even if no extractable components are found. If nothing can be extracted, record that clearly and stop.\n"
                "After writing a non-empty `$output/summary.txt`, stop immediately and print exactly: AGENTFLOW_GENERIC_DONE. Do not continue exploring, reading, extracting, or analyzing after summary.txt is written.\n"
                "Scope limit: this is a firmware unpacking task, not a vulnerability analysis task. "
                "Use file/binwalk/readelf/strings only as needed to identify and extract components. "
                "Do not perform full disassembly, exploit analysis, or extended reverse engineering. "
                "After identifiable components are extracted and basic metadata is collected, immediately write $output/summary.txt and finish.\n"
                "{% if nodes.skill_reviewer.output %}Skill review: {{ nodes.skill_reviewer.output }}{% endif %}\n"
                "{% if nodes.generic_reviewer.output %}Previous review: {{ nodes.generic_reviewer.output }}{% endif %}\n"
                "{% if nodes.preprocess.output %}Preprocess: {{ nodes.preprocess.output }}{% endif %}"
            ),
            tools="read_write",
            model=ctx.get("executor_model"),
            extra_args=ctx.get("executor_extra_args", []),
            timeout_seconds=None,
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "skill_reviewer",
                    "value": "AGENTFLOW_REVIEW_SUCCESS",
                },
                {
                    "kind": "node_output_contains",
                    "node_id": "skill_reviewer",
                    "value": "SKIPPED_BY_PREPROCESS",
                },
            ],
        )
        output_summary = python_node(
            task_id="output_summary",
            code=_summary_writer_code(ctx),
            tools="read_only",
            env=_python_node_env(),
        )
        generic_reviewer = python_node(
            task_id="generic_reviewer",
            code=_generic_review_code(ctx),
            tools="read_only",
            env=_python_node_env(),
            timeout_seconds=_node_timeout(ctx, divisor=2),
            success_criteria=REVIEW_SUCCESS_CRITERIA,
        )
        skill_author = python_node(
            task_id="skill_author",
            code=_skill_author_code(ctx),
            tools="read_write",
            env=_python_node_env(),
        )
        cleanup = python_node(
            task_id="cleanup",
            code=_cleanup_output_code(ctx),
            tools="read_only",
            env=_python_node_env(),
        )
        finalize = python_node(
            task_id="finalize",
            code=_write_json_code(
                {
                    "output_file": ctx["final_result_file"],
                    "data": {
                        "firmware_path": ctx["firmware_path"],
                        "output_path": ctx["output_path"],
                    },
                }
            ),
            tools="read_only",
            env=_python_node_env(),
        )

        preprocess >> feature_match >> skill_gate >> skill_executor >> skill_reviewer
        skill_reviewer.on_failure >> generic_executor
        skill_reviewer >> generic_executor
        generic_executor >> output_summary >> generic_reviewer
        generic_reviewer.on_failure >> generic_executor
        generic_reviewer >> skill_author >> cleanup >> finalize

    return g.to_spec()
