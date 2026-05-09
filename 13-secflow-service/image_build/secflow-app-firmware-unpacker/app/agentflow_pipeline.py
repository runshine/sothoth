"""AgentFlow pipeline builder for firmware unpacking."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))
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
        "print(f\"AGENTFLOW_PROGRESS stage=preprocess event=start firmware={payload['firmware_path']} output={payload['output_path']}\", flush=True)\n"
        "try:\n"
        "    result = run_preprocess(payload['firmware_path'], payload['output_path'], log_dir=log_dir)\n"
        "except Exception as exc:\n"
        "    result = {'success': False, 'method': None, 'error': str(exc)}\n"
        "Path(payload['output_file']).parent.mkdir(parents=True, exist_ok=True)\n"
        "Path(payload['output_file']).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')\n"
        "artifacts = result.get('artifacts') or result.get('files') or []\n"
        "artifact_count = len(artifacts) if isinstance(artifacts, list) else 0\n"
        "print(f\"AGENTFLOW_PROGRESS stage=preprocess event=finish success={bool(result.get('success'))} method={result.get('method')} artifacts={artifact_count} output_file={payload['output_file']}\", flush=True)\n"
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
        "print(f\"AGENTFLOW_PROGRESS stage=feature_match event=start firmware={payload['firmware_path']} tools_dir={payload['tools_dir']}\", flush=True)\n"
        "try:\n"
        "    features = extract_firmware_features(payload['firmware_path'])\n"
        "    print(f\"AGENTFLOW_PROGRESS stage=feature_match event=features ext={features.get('ext')} magic={features.get('magic_hex')} binwalk_sigs={len(features.get('binwalk_sigs') or [])}\", flush=True)\n"
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
        "    print(f\"AGENTFLOW_PROGRESS stage=feature_match event=error error={exc}\", flush=True)\n"
        "Path(payload['output_file']).parent.mkdir(parents=True, exist_ok=True)\n"
        "Path(payload['output_file']).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')\n"
        "summary = {k: result.get(k) for k in ('matched_skill', 'matched_skill_version', 'matched_skill_score', 'matched_status', 'reasons', 'error') if k in result}\n"
        "summary['feature_family_id'] = (result.get('features') or {}).get('family_id')\n"
        "summary['feature_count_binwalk_sigs'] = len((result.get('features') or {}).get('binwalk_sigs') or [])\n"
        "print(f\"AGENTFLOW_PROGRESS stage=feature_match event=finish matched={bool(result.get('matched_skill'))} score={result.get('matched_skill_score')} output_file={payload['output_file']}\", flush=True)\n"
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
        "print(f\"AGENTFLOW_PROGRESS stage=skill_gate event=start feature_file={payload['feature_match_output_file']}\", flush=True)\n"
        "try:\n"
        "    data = json.loads(Path(payload['feature_match_output_file']).read_text(encoding='utf-8'))\n"
        "except Exception as exc:\n"
        "    print(f'AGENTFLOW_PROGRESS stage=skill_gate event=error error={exc}', flush=True)\n"
        "    print(f'AGENTFLOW_SKILL_GATE matched=false reason=FEATURE_MATCH_UNREADABLE error={exc}')\n"
        "else:\n"
        "    matched = data.get('matched_skill')\n"
        "    if matched:\n"
        "        print(f'AGENTFLOW_PROGRESS stage=skill_gate event=finish matched=true score={data.get(\"matched_skill_score\")}', flush=True)\n"
        "        print(f'AGENTFLOW_SKILL_GATE matched=true skill={matched}')\n"
        "    else:\n"
        "        reason = data.get('matched_status') or 'SKIPPED_NO_SKILL'\n"
        "        print(f'AGENTFLOW_PROGRESS stage=skill_gate event=finish matched=false reason={reason}', flush=True)\n"
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
        "print(f\"AGENTFLOW_PROGRESS stage=output_summary event=start output={output} summary={summary}\", flush=True)\n"
        "summary.parent.mkdir(parents=True, exist_ok=True)\n"
        "if summary.exists() and summary.stat().st_size > 0:\n"
        "    print(f\"AGENTFLOW_PROGRESS stage=output_summary event=finish reused=true bytes={summary.stat().st_size}\", flush=True)\n"
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
        "    print(f\"AGENTFLOW_PROGRESS stage=output_summary event=finish reused=false artifacts={len(files)} bytes={summary.stat().st_size}\", flush=True)\n"
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
        "print(f\"AGENTFLOW_PROGRESS stage=cleanup event=start output={output}\", flush=True)\n"
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
        "print(f\"AGENTFLOW_PROGRESS stage=cleanup event=finish removed_files={len(removed_files)} removed_dirs={len(removed_dirs)}\", flush=True)\n"
        "print(json.dumps({'removed_files': removed_files, 'removed_dirs': removed_dirs}, ensure_ascii=False))\n"
    )


def _finalize_result_code(ctx: dict[str, Any]) -> str:
    payload = {
        "firmware_path": ctx["firmware_path"],
        "output_path": ctx["output_path"],
        "tools_dir": ctx["tools_dir"],
        "feature_match_output_file": ctx["feature_match_output_file"],
        "skill_author_output_file": ctx["skill_author_output_file"],
        "final_result_file": ctx["final_result_file"],
        "stage2_file": str(Path(ctx["final_result_file"]).parent / "stage2_skill_match.json"),
        "stage3_file": str(Path(ctx["final_result_file"]).parent / "stage3_skill_exec.json"),
        "stage4_file": str(Path(ctx["final_result_file"]).parent / "stage4_llm_fallback.json"),
        "stage5_file": str(Path(ctx["final_result_file"]).parent / "stage5_skill_generate.json"),
    }
    return (
        "import json\n"
        "import re\n"
        "from pathlib import Path\n\n"
        "from app.skill_store import register_skill_success, save_candidate_skill\n\n"
        f"payload = json.loads(r'''{json.dumps(payload, ensure_ascii=False)}''')\n"
        "preprocess_output = r'''{{ nodes.preprocess.output }}'''\n"
        "feature_output = r'''{{ nodes.feature_match.output }}'''\n"
        "skill_output = r'''{{ nodes.skill_executor.output }}'''\n"
        "skill_review = r'''{{ nodes.skill_reviewer.output }}'''\n"
        "generic_output = r'''{{ nodes.generic_executor.output }}'''\n"
        "generic_review = r'''{{ nodes.generic_reviewer.output }}'''\n"
        "author_output = r'''{{ nodes.skill_author.output }}'''\n"
        "cleanup_output = r'''{{ nodes.cleanup.output }}'''\n"
        "skill_status = r'''{{ nodes.skill_executor.status }}'''.strip()\n"
        "generic_status = r'''{{ nodes.generic_executor.status }}'''.strip()\n\n"
        "def write_json(path, data):\n"
        "    target = Path(path)\n"
        "    target.parent.mkdir(parents=True, exist_ok=True)\n"
        "    target.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')\n\n"
        "def parse_json_text(text):\n"
        "    raw = str(text or '').strip()\n"
        "    if not raw:\n"
        "        return {}\n"
        "    try:\n"
        "        return json.loads(raw)\n"
        "    except Exception:\n"
        "        pass\n"
        "    for line in reversed(raw.splitlines()):\n"
        "        candidate = line.strip()\n"
        "        if not candidate or candidate[0] not in '{[':\n"
        "            continue\n"
        "        try:\n"
        "            return json.loads(candidate)\n"
        "        except Exception:\n"
        "            continue\n"
        "    return {}\n\n"
        "def preview(text, limit=320):\n"
        "    compact = ' '.join(str(text or '').split())\n"
        "    return compact if len(compact) <= limit else compact[:limit] + '...'\n\n"
        "def review_success(text):\n"
        "    raw = str(text or '')\n"
        "    if 'AGENTFLOW_REVIEW_SUCCESS' in raw:\n"
        "        return True\n"
        "    lowered = raw.lower()\n"
        "    return '\"result\"' in lowered and '\"success\"' in lowered\n\n"
        "def review_skipped(text):\n"
        "    return 'AGENTFLOW_REVIEW_SKIPPED' in str(text or '')\n\n"
        "def extract_markdown_document(text):\n"
        "    raw = str(text or '').strip()\n"
        "    if raw.startswith('```'):\n"
        "        raw = re.sub(r'^```[a-zA-Z0-9_-]*\\n', '', raw)\n"
        "        raw = re.sub(r'\\n```$', '', raw)\n"
        "    return raw.strip()\n\n"
        "preprocess_data = parse_json_text(preprocess_output)\n"
        "print(f\"AGENTFLOW_PROGRESS stage=finalize event=start preprocess_success={bool(preprocess_data.get('success'))}\", flush=True)\n"
        "try:\n"
        "    feature_payload = json.loads(Path(payload['feature_match_output_file']).read_text(encoding='utf-8'))\n"
        "except Exception:\n"
        "    feature_payload = parse_json_text(feature_output)\n"
        "features = feature_payload.get('features') or {}\n"
        "matched_skill_path = feature_payload.get('matched_skill')\n"
        "matched_skill_version = feature_payload.get('matched_skill_version')\n"
        "matched_skill_score = feature_payload.get('matched_skill_score')\n"
        "preprocess_passed = bool(preprocess_data.get('success'))\n"
        "skill_passed = skill_status not in {'failed', 'cancelled'} and review_success(skill_review)\n"
        "generic_passed = generic_status not in {'failed', 'cancelled'} and review_success(generic_review)\n"
        "passed = preprocess_passed or skill_passed or generic_passed\n"
        "fallback_to_llm = bool(matched_skill_path and not skill_passed)\n"
        "generated_skill = None\n"
        "skill_update_error = None\n"
        "generated_skill_error = None\n"
        "matched_skill_after_update = matched_skill_path\n"
        "promotion_success_count = None\n\n"
        "if passed and skill_passed and matched_skill_path:\n"
        "    try:\n"
        "        updated_skill = register_skill_success(Path(payload['tools_dir']), matched_skill_path)\n"
        "        matched_skill_after_update = updated_skill.get('path')\n"
        "        matched_skill_version = updated_skill.get('skill_version')\n"
        "        promotion_success_count = updated_skill.get('promotion_success_count')\n"
        "    except Exception as exc:\n"
        "        skill_update_error = str(exc)\n\n"
        "author_file = Path(payload['skill_author_output_file'])\n"
        "if author_file.is_file():\n"
        "    author_output = author_file.read_text(encoding='utf-8', errors='replace')\n"
        "if passed and generic_passed and author_output.strip() and 'SKIPPED' not in author_output:\n"
        "    try:\n"
        "        generated_skill = save_candidate_skill(\n"
        "            Path(payload['tools_dir']),\n"
        "            extract_markdown_document(author_output),\n"
        "            {\n"
        "                'family_id': features.get('family_id') or 'generic-firmware',\n"
        "                'source_run_id': '',\n"
        "                'source_node_id': 'generic_executor',\n"
        "            },\n"
        "        )\n"
        "    except Exception as exc:\n"
        "        generated_skill_error = str(exc)\n\n"
        "failure_summary = {'failed_nodes': []}\n"
        "if not passed:\n"
        "    reason = generic_review or skill_review or generic_output or skill_output\n"
        "    failure_summary['failed_nodes'].append({\n"
        "        'node_id': 'generic_reviewer' if generic_output else 'skill_reviewer',\n"
        "        'classification': {'failure_category': 'non_retryable', 'reason': preview(reason, 180)},\n"
        "        'output_preview': preview(reason),\n"
        "    })\n\n"
        "result = {\n"
        "    'status': 'success' if passed else 'failed',\n"
        "    'message': 'Unpacking verified successfully' if passed else 'AgentFlow run failed',\n"
        "    'rounds': 0 if preprocess_passed or skill_passed else (1 if generic_output.strip() else 0),\n"
        "    'matched_skill': matched_skill_after_update,\n"
        "    'matched_skill_version': matched_skill_version,\n"
        "    'matched_skill_score': matched_skill_score if matched_skill_after_update else None,\n"
        "    'fallback_to_llm': fallback_to_llm,\n"
        "    'generated_skill_path': generated_skill.get('path') if generated_skill else None,\n"
        "    'generated_skill_status': generated_skill.get('skill_status') if generated_skill else None,\n"
        "    'promotion_success_count': promotion_success_count if promotion_success_count is not None else (generated_skill.get('promotion_success_count') if generated_skill else None),\n"
        "    'firmware_path': payload['firmware_path'],\n"
        "    'output_path': payload['output_path'],\n"
        "    'run_path': str(Path(payload['final_result_file']).parent),\n"
        "    'node_attempts': {\n"
        "        'skill_executor': {'status': skill_status},\n"
        "        'generic_executor': {'status': generic_status},\n"
        "    },\n"
        "    'failure_summary': failure_summary,\n"
        "    'failure_category': failure_summary['failed_nodes'][0]['classification']['failure_category'] if failure_summary['failed_nodes'] else None,\n"
        "    'total_tokens': 0,\n"
        "    'skill_update_error': skill_update_error,\n"
        "    'generated_skill_error': generated_skill_error,\n"
        "}\n"
        "write_json(payload['stage2_file'], feature_payload)\n"
        "write_json(payload['stage3_file'], {\n"
        "    'skill': matched_skill_path,\n"
        "    'success': passed,\n"
        "    'skill_status': skill_status,\n"
        "    'response_preview': preview(skill_output or generic_output),\n"
        "    'review_preview': preview(skill_review or generic_review),\n"
        "})\n"
        "write_json(payload['stage4_file'], {\n"
        "    'matched_skill': matched_skill_path,\n"
        "    'fallback_to_llm': fallback_to_llm,\n"
        "    'reason': preview(generic_review or skill_review, 400),\n"
        "})\n"
        "write_json(payload['stage5_file'], {\n"
        "    'generated_skill_path': generated_skill.get('path') if generated_skill else None,\n"
        "    'generated_skill_status': generated_skill.get('skill_status') if generated_skill else None,\n"
        "    'promotion_success_count': promotion_success_count,\n"
        "    'source_node_id': 'generic_executor' if generated_skill else None,\n"
        "    'error': generated_skill_error,\n"
        "})\n"
        "write_json(payload['final_result_file'], result)\n"
        "print(f\"AGENTFLOW_PROGRESS stage=finalize event=finish status={result['status']} fallback_to_llm={result['fallback_to_llm']} generated_skill={bool(result['generated_skill_path'])}\", flush=True)\n"
        "print(json.dumps(result, ensure_ascii=False))\n"
    )


def _preprocess_finalize_code(ctx: dict[str, Any]) -> str:
    payload = {
        "firmware_path": ctx["firmware_path"],
        "output_path": ctx["output_path"],
        "feature_match_output_file": ctx["feature_match_output_file"],
        "final_result_file": ctx["final_result_file"],
        "stage2_file": str(Path(ctx["final_result_file"]).parent / "stage2_skill_match.json"),
        "stage3_file": str(Path(ctx["final_result_file"]).parent / "stage3_skill_exec.json"),
        "stage4_file": str(Path(ctx["final_result_file"]).parent / "stage4_llm_fallback.json"),
        "stage5_file": str(Path(ctx["final_result_file"]).parent / "stage5_skill_generate.json"),
    }
    return (
        "import json\n"
        "from pathlib import Path\n\n"
        f"payload = json.loads(r'''{json.dumps(payload, ensure_ascii=False)}''')\n"
        "preprocess_output = r'''{{ nodes.preprocess.output }}'''\n"
        "feature_output = r'''{{ nodes.feature_match.output }}'''\n\n"
        "def write_json(path, data):\n"
        "    target = Path(path)\n"
        "    target.parent.mkdir(parents=True, exist_ok=True)\n"
        "    target.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')\n\n"
        "def parse_json_text(text):\n"
        "    raw = str(text or '').strip()\n"
        "    if not raw:\n"
        "        return {}\n"
        "    try:\n"
        "        return json.loads(raw)\n"
        "    except Exception:\n"
        "        pass\n"
        "    for line in reversed(raw.splitlines()):\n"
        "        candidate = line.strip()\n"
        "        if not candidate or candidate[0] not in '{[':\n"
        "            continue\n"
        "        try:\n"
        "            return json.loads(candidate)\n"
        "        except Exception:\n"
        "            continue\n"
        "    return {}\n\n"
        "preprocess_data = parse_json_text(preprocess_output)\n"
        "print(f\"AGENTFLOW_PROGRESS stage=preprocess_finalize event=start preprocess_success={bool(preprocess_data.get('success'))}\", flush=True)\n"
        "if not preprocess_data.get('success'):\n"
        "    print('AGENTFLOW_PROGRESS stage=preprocess_finalize event=skip reason=NO_PREPROCESS_SUCCESS', flush=True)\n"
        "    print('SKIPPED_NO_PREPROCESS_SUCCESS')\n"
        "else:\n"
        "    try:\n"
        "        feature_payload = json.loads(Path(payload['feature_match_output_file']).read_text(encoding='utf-8'))\n"
        "    except Exception:\n"
        "        feature_payload = parse_json_text(feature_output)\n"
        "    matched_skill_path = feature_payload.get('matched_skill')\n"
        "    matched_skill_version = feature_payload.get('matched_skill_version')\n"
        "    matched_skill_score = feature_payload.get('matched_skill_score')\n"
        "    result = {\n"
        "        'status': 'success',\n"
        "        'message': 'Unpacking verified successfully',\n"
        "        'rounds': 0,\n"
        "        'matched_skill': matched_skill_path,\n"
        "        'matched_skill_version': matched_skill_version,\n"
        "        'matched_skill_score': matched_skill_score if matched_skill_path else None,\n"
        "        'fallback_to_llm': False,\n"
        "        'generated_skill_path': None,\n"
        "        'generated_skill_status': None,\n"
        "        'promotion_success_count': None,\n"
        "        'firmware_path': payload['firmware_path'],\n"
        "        'output_path': payload['output_path'],\n"
        "        'run_path': str(Path(payload['final_result_file']).parent),\n"
        "        'node_attempts': {\n"
        "            'skill_executor': {'status': 'skipped'},\n"
        "            'generic_executor': {'status': 'skipped'},\n"
        "        },\n"
        "        'failure_summary': {'failed_nodes': []},\n"
        "        'failure_category': None,\n"
        "        'total_tokens': 0,\n"
        "        'skill_update_error': None,\n"
        "        'generated_skill_error': None,\n"
        "    }\n"
        "    write_json(payload['stage2_file'], feature_payload)\n"
        "    write_json(payload['stage3_file'], {\n"
        "        'skill': matched_skill_path,\n"
        "        'success': True,\n"
        "        'skill_status': 'skipped',\n"
        "        'response_preview': str(preprocess_output or '').strip(),\n"
        "        'review_preview': 'SKIPPED_BY_PREPROCESS',\n"
        "    })\n"
        "    write_json(payload['stage4_file'], {\n"
        "        'matched_skill': matched_skill_path,\n"
        "        'fallback_to_llm': False,\n"
        "        'reason': 'preprocess_success_short_circuit',\n"
        "    })\n"
        "    write_json(payload['stage5_file'], {\n"
        "        'generated_skill_path': None,\n"
        "        'generated_skill_status': None,\n"
        "        'promotion_success_count': None,\n"
        "        'source_node_id': None,\n"
        "        'error': None,\n"
        "    })\n"
        "    write_json(payload['final_result_file'], result)\n"
        "    print(f\"AGENTFLOW_PROGRESS stage=preprocess_finalize event=finish status={result['status']} matched_skill={matched_skill_path}\", flush=True)\n"
        "    print(json.dumps(result, ensure_ascii=False))\n"
    )


def _skill_review_code() -> str:
    return (
        "print('AGENTFLOW_PROGRESS stage=skill_reviewer event=start', flush=True)\n"
        "executor_status = r'''{{ nodes.skill_executor.status }}'''.strip()\n"
        "executor_output = r'''{{ nodes.skill_executor.output }}'''\n"
        "if 'AGENTFLOW_EXECUTOR_SKIPPED' in executor_output or 'SKIPPED' in executor_output:\n"
        "    reason = 'SKIPPED_NO_SKILL'\n"
        "    if 'reason=' in executor_output:\n"
        "        reason = executor_output.split('reason=', 1)[1].split()[0].strip()\n"
        "    print(f'AGENTFLOW_PROGRESS stage=skill_reviewer event=finish result=skipped reason={reason}', flush=True)\n"
        "    print(f'AGENTFLOW_REVIEW_SKIPPED reason={reason}')\n"
        "elif executor_status != 'completed':\n"
        "    print(f'AGENTFLOW_PROGRESS stage=skill_reviewer event=finish result=fail executor_status={executor_status}', flush=True)\n"
        "    print('AGENTFLOW_REVIEW_FAIL category=STRUCTURAL_FAILURE reason=executor_failed')\n"
        "elif any(token in executor_output.lower() for token in ('fail', 'failed', 'invalid', 'error')):\n"
        "    print('AGENTFLOW_PROGRESS stage=skill_reviewer event=finish result=fail reason=executor_reported_failure', flush=True)\n"
        "    print('AGENTFLOW_REVIEW_FAIL category=STRUCTURAL_FAILURE reason=executor_reported_failure')\n"
        "elif executor_output.strip():\n"
        "    print('AGENTFLOW_PROGRESS stage=skill_reviewer event=finish result=success', flush=True)\n"
        "    print('AGENTFLOW_REVIEW_SUCCESS')\n"
        "else:\n"
        "    print('AGENTFLOW_PROGRESS stage=skill_reviewer event=finish result=fail reason=empty_executor_output', flush=True)\n"
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
        "print('AGENTFLOW_PROGRESS stage=generic_reviewer event=start', flush=True)\n"
        "executor_status = r'''{{ nodes.generic_executor.status }}'''.strip()\n"
        "executor_output = r'''{{ nodes.generic_executor.output }}'''\n"
        "if 'AGENTFLOW_EXECUTOR_SKIPPED' in executor_output or 'SKIPPED' in executor_output:\n"
        "    reason = 'SKIPPED'\n"
        "    if 'reason=' in executor_output:\n"
        "        reason = executor_output.split('reason=', 1)[1].split()[0].strip()\n"
        "    print(f'AGENTFLOW_PROGRESS stage=generic_reviewer event=finish result=skipped reason={reason}', flush=True)\n"
        "    print(f'AGENTFLOW_REVIEW_SKIPPED reason={reason}')\n"
        "elif executor_status != 'completed':\n"
        "    print(f'AGENTFLOW_PROGRESS stage=generic_reviewer event=finish result=fail executor_status={executor_status}', flush=True)\n"
        "    print('AGENTFLOW_REVIEW_FAIL category=STRUCTURAL_FAILURE reason=executor_failed')\n"
        "else:\n"
        "    output = Path(payload['output_path'])\n"
        "    summary = output / 'summary.txt'\n"
        "    artifacts = [p for p in output.rglob('*') if p.is_file() and p.name not in {'summary.txt', 'reason.txt'}]\n"
        "    if not summary.is_file() or summary.stat().st_size == 0:\n"
        "        print('AGENTFLOW_PROGRESS stage=generic_reviewer event=finish result=fail reason=missing_summary', flush=True)\n"
        "        print('AGENTFLOW_REVIEW_FAIL category=STRUCTURAL_FAILURE reason=missing_summary')\n"
        "    elif not artifacts:\n"
        "        print('AGENTFLOW_PROGRESS stage=generic_reviewer event=finish result=fail reason=empty_output', flush=True)\n"
        "        print('AGENTFLOW_REVIEW_FAIL category=CONTENT_MISSING reason=empty_output')\n"
        "    else:\n"
        "        print(f'AGENTFLOW_PROGRESS stage=generic_reviewer event=finish result=success artifacts={len(artifacts)}', flush=True)\n"
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
        "print('AGENTFLOW_PROGRESS stage=skill_author event=start', flush=True)\n"
        "if 'AGENTFLOW_REVIEW_SUCCESS' not in review:\n"
        "    print('AGENTFLOW_PROGRESS stage=skill_author event=skip reason=NO_GENERIC_SUCCESS', flush=True)\n"
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
        "    raw_sigs = []\n"
        "    seen_sigs = set()\n"
        "    for item in features.get('binwalk_sigs') or []:\n"
        "        sig = ' '.join(str(item).split())[:60]\n"
        "        if sig and sig not in seen_sigs:\n"
            "            raw_sigs.append(sig)\n"
            "            seen_sigs.add(sig)\n"
        "        if len(raw_sigs) >= 8:\n"
            "            break\n"
        "    sigs = ', '.join(raw_sigs)\n"
        "    if not sigs:\n"
        "        sigs = 'firmware'\n"
        "    summary = Path(payload['output_path']) / 'summary.txt'\n"
        "    raw_summary = summary.read_text(encoding='utf-8', errors='replace') if summary.is_file() else ''\n"
        "    summary_lines = []\n"
        "    for line in raw_summary.splitlines():\n"
        "        compact = ' '.join(line.split())\n"
        "        if compact:\n"
        "            summary_lines.append(compact[:500])\n"
        "        if len(summary_lines) >= 80:\n"
        "            break\n"
        "    summary_text = '\\n'.join(summary_lines)\n"
        "    if len(raw_summary.splitlines()) > len(summary_lines) or len(raw_summary) > len(summary_text):\n"
        "        summary_text += '\\n[summary truncated for reusable skill size]'\n"
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
        "    print(f\"AGENTFLOW_PROGRESS stage=skill_author event=finish output_file={payload['skill_author_output_file']}\", flush=True)\n"
        "    print(f\"AGENTFLOW_SKILL_AUTHOR_WRITTEN path={payload['skill_author_output_file']}\")\n"
    )


def _input_path(ctx: dict[str, Any]) -> str:
    return str(ctx.get("input_path") or Path(ctx["firmware_path"]).parent)


def _executor_env(ctx: dict[str, Any]) -> dict[str, str]:
    """Expose task paths to Pi and its bash tool exactly as the prompts name them."""
    input_path = _input_path(ctx)
    firmware_path = str(ctx["firmware_path"])
    output_path = str(ctx["output_path"])
    return {
        "input": input_path,
        "firmware": firmware_path,
        "output": output_path,
        "FIRMWARE_INPUT": input_path,
        "FIRMWARE_PATH": firmware_path,
        "FIRMWARE_OUTPUT": output_path,
    }


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
                "These variables are exported in the bash tool environment; use them quoted exactly as shown.\n"
                "Use $output exactly as the output directory. Do not write results to its parent directory.\n"
                "Skill gate: {{ nodes.skill_gate.output }}\n"
                "Preprocess: {{ nodes.preprocess.output }}\n"
            ),
            tools="read_write",
            model=ctx.get("executor_model"),
            env=_executor_env(ctx),
            extra_args=ctx.get("executor_extra_args", []),
            timeout_seconds=None,
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "preprocess",
                    "value": '"success": true',
                },
                {
                    "kind": "node_output_contains",
                    "node_id": "skill_gate",
                    "value": "matched=false",
                },
            ],
        )
        skill_reviewer = python_node(
            task_id="skill_reviewer",
            code=_skill_review_code(),
            tools="read_only",
            env=_python_node_env(),
            timeout_seconds=_node_timeout(ctx, divisor=2),
            success_criteria=REVIEW_SUCCESS_CRITERIA,
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "preprocess",
                    "value": '"success": true',
                },
                {
                    "kind": "node_output_contains",
                    "node_id": "skill_gate",
                    "value": "matched=false",
                },
            ],
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
                "These variables are exported in the bash tool environment; use them quoted exactly as shown.\n"
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
            env=_executor_env(ctx),
            extra_args=ctx.get("executor_extra_args", []),
            timeout_seconds=None,
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "preprocess",
                    "value": '"success": true',
                },
                {
                    "kind": "node_output_contains",
                    "node_id": "skill_reviewer",
                    "value": "AGENTFLOW_REVIEW_SUCCESS",
                },
            ],
        )
        output_summary = python_node(
            task_id="output_summary",
            code=_summary_writer_code(ctx),
            tools="read_only",
            env=_python_node_env(),
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "preprocess",
                    "value": '"success": true',
                },
            ],
        )
        generic_reviewer = python_node(
            task_id="generic_reviewer",
            code=_generic_review_code(ctx),
            tools="read_only",
            env=_python_node_env(),
            timeout_seconds=_node_timeout(ctx, divisor=2),
            success_criteria=REVIEW_SUCCESS_CRITERIA,
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "preprocess",
                    "value": '"success": true',
                },
            ],
        )
        skill_author = python_node(
            task_id="skill_author",
            code=_skill_author_code(ctx),
            tools="read_write",
            env=_python_node_env(),
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "preprocess",
                    "value": '"success": true',
                },
            ],
        )
        preprocess_finalize = python_node(
            task_id="preprocess_finalize",
            code=_preprocess_finalize_code(ctx),
            tools="read_only",
            env=_python_node_env(),
        )
        cleanup = python_node(
            task_id="cleanup",
            code=_cleanup_output_code(ctx),
            tools="read_only",
            env=_python_node_env(),
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "preprocess",
                    "value": '"success": true',
                },
            ],
        )
        finalize = python_node(
            task_id="finalize",
            code=_finalize_result_code(ctx),
            tools="read_only",
            env=_python_node_env(),
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "preprocess",
                    "value": '"success": true',
                },
            ],
        )

        preprocess >> feature_match >> skill_gate >> skill_executor >> skill_reviewer
        skill_gate >> preprocess_finalize
        skill_reviewer.on_failure >> generic_executor
        skill_reviewer >> generic_executor
        generic_executor >> output_summary >> generic_reviewer
        generic_reviewer.on_failure >> generic_executor
        generic_reviewer >> skill_author >> cleanup >> finalize

    return g.to_spec()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _first_env(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def _load_agent_defs_for_pipeline() -> dict[str, dict[str, Any]]:
    from app.unpacker_engine import (
        AUTHOR_AGENT_DEF,
        CLEAN_AGENT_DEF,
        EXEC_AGENT_DEF,
        VAL_AGENT_DEF,
        load_agent_def,
    )

    return {
        "exec": load_agent_def(EXEC_AGENT_DEF),
        "review": load_agent_def(VAL_AGENT_DEF),
        "author": load_agent_def(AUTHOR_AGENT_DEF),
        "cleanup": load_agent_def(CLEAN_AGENT_DEF),
    }


def _materialize_system_prompts(run_dir: Path, agent_defs: dict[str, dict[str, Any]]) -> dict[str, Path]:
    prompt_dir = run_dir / "system-prompts"
    prompt_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for key, agent_def in agent_defs.items():
        path = prompt_dir / f"{key}.md"
        path.write_text(str(agent_def.get("system_prompt") or ""), encoding="utf-8")
        paths[key] = path
    return paths


def build_firmware_unpack_context_from_env() -> dict[str, Any]:
    firmware = _first_env("FIRMWARE_PATH", "firmware")
    output = _first_env("OUTPUT_PATH", "FIRMWARE_OUTPUT", "output")
    if not firmware or not output:
        raise ValueError(
            "FIRMWARE_PATH and OUTPUT_PATH are required when running app/agentflow_pipeline.py directly"
        )

    firmware_path = Path(firmware).expanduser().resolve()
    output_path = Path(output).expanduser().resolve()
    task_dir = Path(_first_env("TASK_DIR", "BASE_DIR") or output_path.parent).expanduser().resolve()
    run_dir = Path(_first_env("RUN_PATH", "LOG_PATH", "FIRMWARE_RUN_PATH") or task_dir / "run").expanduser().resolve()
    tools_dir = Path(
        _first_env("TOOLS_DIR", "UNPACKER_TOOLS_DIR") or _repo_root / "tools"
    ).expanduser().resolve()
    input_path = Path(_first_env("INPUT_PATH", "FIRMWARE_INPUT") or firmware_path.parent).expanduser().resolve()

    output_path.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)
    tools_dir.mkdir(parents=True, exist_ok=True)

    agent_defs = _load_agent_defs_for_pipeline()
    prompt_paths = _materialize_system_prompts(run_dir, agent_defs)

    graph_optimization_enabled = _env_bool("AGENTFLOW_GRAPH_OPTIMIZATION_ENABLED", False)
    graph_optimization_rounds = _env_int("AGENTFLOW_GRAPH_OPTIMIZATION_ROUNDS", 1)

    return {
        "base_dir": str(task_dir),
        "task_dir": str(task_dir),
        "input_path": str(input_path),
        "firmware_path": str(firmware_path),
        "firmware_name": firmware_path.name,
        "output_path": str(output_path),
        "log_dir": str(run_dir),
        "tools_dir": str(tools_dir),
        "max_retries": _env_int("MAX_RETRIES", _env_int("AGENTFLOW_MAX_ITERATIONS", 5)),
        "node_timeout_seconds": _env_int("AGENTFLOW_NODE_TIMEOUT_SECONDS", 1800),
        "agentflow_concurrency": _env_int("AGENTFLOW_MAX_CONCURRENT_RUNS", 2),
        "use_worktree": _env_bool("AGENTFLOW_USE_WORKTREE", False),
        "graph_optimization_enabled": graph_optimization_enabled and graph_optimization_rounds > 1,
        "graph_optimizer": os.environ.get("AGENTFLOW_GRAPH_OPTIMIZER", "codex"),
        "graph_optimization_rounds": graph_optimization_rounds,
        "preprocess_output_file": str(run_dir / "preprocess.json"),
        "feature_match_output_file": str(run_dir / "feature-match.json"),
        "skill_author_output_file": str(run_dir / "generated_skill.md"),
        "final_result_file": str(run_dir / "final_result.json"),
        "executor_model": agent_defs["exec"].get("model"),
        "review_model": agent_defs["review"].get("model"),
        "author_model": agent_defs["author"].get("model"),
        "cleanup_model": agent_defs["cleanup"].get("model"),
        "executor_extra_args": ["--append-system-prompt", str(prompt_paths["exec"])],
        "review_extra_args": ["--append-system-prompt", str(prompt_paths["review"])],
        "author_extra_args": ["--append-system-prompt", str(prompt_paths["author"])],
        "cleanup_extra_args": ["--append-system-prompt", str(prompt_paths["cleanup"])],
    }


def main() -> None:
    try:
        ctx = build_firmware_unpack_context_from_env()
        spec = build_firmware_unpack_pipeline(ctx)
    except Exception as exc:
        print(f"failed to build firmware unpack pipeline: {exc}", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(spec.model_dump(mode="json"), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
