from __future__ import annotations

import os
import re
from typing import Any

from app.pi_vuln_core.utils.file_ops import read_file
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("previous_limitations")


def extract_markdown_section(content: str, titles: list[str]) -> str:
    if not content:
        return ""
    lines = content.splitlines()
    start_idx = None
    start_level = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("#"):
            continue
        level = len(stripped) - len(stripped.lstrip("#"))
        normalized = re.sub(r"^#+\s*", "", stripped)
        normalized = re.sub(r"^\d+(?:\.\d+)*\s*[.、]?\s*", "", normalized).strip()
        if any(title in normalized for title in titles):
            start_idx = i
            start_level = level
            break
    if start_idx is None or start_level is None:
        return ""

    end_idx = len(lines)
    for j in range(start_idx + 1, len(lines)):
        stripped = lines[j].strip()
        if not stripped.startswith("#"):
            continue
        level = len(stripped) - len(stripped.lstrip("#"))
        if level <= start_level:
            end_idx = j
            break
    return "\n".join(lines[start_idx:end_idx]).strip()


def is_substantive_limitations(content: str) -> bool:
    if not content or not content.strip():
        return False

    payload_lines: list[str] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        normalized = re.sub(r"^#+\s*", "", line)
        normalized = re.sub(r"^\d+(?:\.\d+)*\s*[.、]?\s*", "", normalized).strip()
        if "局限性与未覆盖区域" in normalized or normalized == "局限性":
            continue
        if "详见" in line and "previous_limitations" in line:
            continue
        if re.fullmatch(r"[>`*_\-\s]+", line):
            continue
        payload_lines.append(line)

    return bool(payload_lines)


def load_previous_limitations(
    work_dir: str,
    cycle: int,
) -> tuple[str, dict[str, Any]]:
    """
    读取供当前轮核查/返工使用的“上一轮局限性记录”。

    优先级：
    1. 上一轮 `previous_limitations.md` 的专用快照
    2. 上一轮 summary 快照中的“局限性与未覆盖区域”章节
    3. 工作目录中的 `previous_limitations.md`（历史运行兼容回退）
    """
    if cycle <= 1:
        return (
            "(首轮评审，无上一轮“局限性与未覆盖区域”记录)",
            {
                "kind": "initial",
                "path": "",
                "cycle": 0,
                "fallback": False,
            },
        )

    previous_cycle = cycle - 1
    sidecar_candidates = [
        os.path.join(
            work_dir,
            "_meta",
            "previous_limitations_snapshots",
            f"cycle_{previous_cycle:03d}_previous_limitations.md",
        ),
    ]
    summary_candidates = [
        os.path.join(
            work_dir,
            "_meta",
            "summary_snapshots",
            f"cycle_{previous_cycle:03d}_after_summary.md",
        ),
        os.path.join(
            work_dir,
            "_meta",
            "summary_versions",
            f"cycle_{previous_cycle:03d}_after_summary.md",
        ),
    ]

    for path in sidecar_candidates:
        if not os.path.isfile(path):
            continue
        try:
            content = read_file(path)
            if is_substantive_limitations(content):
                return (
                    content,
                    {
                        "kind": "sidecar_snapshot",
                        "path": path,
                        "cycle": previous_cycle,
                        "fallback": False,
                    },
                )
        except Exception as exc:
            logger.warning(
                "previous_limitations_read_failed",
                path=path,
                error=str(exc),
            )

    for path in summary_candidates:
        if not os.path.isfile(path):
            continue
        try:
            content = read_file(path)
            section = extract_markdown_section(
                content,
                ["局限性与未覆盖区域", "局限性"],
            )
            if is_substantive_limitations(section):
                return (
                    section,
                    {
                        "kind": "summary_snapshot",
                        "path": path,
                        "cycle": previous_cycle,
                        "fallback": False,
                    },
                )
        except Exception as exc:
            logger.warning(
                "previous_limitations_read_failed",
                path=path,
                error=str(exc),
            )

    workspace_limitations = os.path.join(work_dir, "previous_limitations.md")
    if os.path.isfile(workspace_limitations):
        try:
            content = read_file(workspace_limitations)
            if is_substantive_limitations(content):
                note = (
                    "> 注：上一轮局限性快照缺失或仅为占位内容；以下回退自工作目录 "
                    "`previous_limitations.md`，可能已包含本轮更新，请结合 summary 时间线审阅。"
                )
                return (
                    f"{note}\n\n{content}",
                    {
                        "kind": "workspace_fallback",
                        "path": workspace_limitations,
                        "cycle": previous_cycle,
                        "fallback": True,
                    },
                )
        except Exception as exc:
            logger.warning(
                "previous_limitations_read_failed",
                path=workspace_limitations,
                error=str(exc),
            )

    return (
        "(未找到上一轮“局限性与未覆盖区域”章节快照)",
        {
            "kind": "missing",
            "path": "",
            "cycle": previous_cycle,
            "fallback": True,
        },
    )
