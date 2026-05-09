"""Agent definition paths and frontmatter parsing."""

from __future__ import annotations

import os
import re
from pathlib import Path


AGENT_DIR = Path(
    os.environ.get(
        "UNPACKER_AGENT_DIR",
        str(Path(__file__).resolve().parent),
    )
)

EXEC_AGENT_DEF = str(AGENT_DIR / "firmware-unpacker.md")
VAL_AGENT_DEF = str(AGENT_DIR / "firmware-unpack-reviewer.md")
CLEAN_AGENT_DEF = str(AGENT_DIR / "firmware-extract-cleanup.md")
AUTHOR_AGENT_DEF = str(AGENT_DIR / "firmware-skill-author.md")

EXEC_FIRST_TMPL = AGENT_DIR / "prompt" / "unpack-firmware.md"
EXEC_RETRY_TMPL = AGENT_DIR / "prompt" / "retry-firmware-unpack.md"
VAL_PROMPT_TMPL = AGENT_DIR / "prompt" / "review-firmware-unpack.md"
CLEAN_PROMPT_TMPL = AGENT_DIR / "prompt" / "cleanup-firmware.md"
AUTHOR_PROMPT_TMPL = AGENT_DIR / "prompt" / "author-firmware-skill.md"


def load_agent_def(md_path: str) -> dict:
    content = Path(md_path).read_text()
    match = re.match(r"^---\n(.*?)\n---\n(.*)$", content, re.DOTALL)
    if not match:
        raise ValueError(f"Invalid agent definition (missing frontmatter): {md_path}")

    fm: dict[str, str] = {}
    for line in match.group(1).split("\n"):
        if ":" in line:
            key, _, value = line.partition(":")
            fm[key.strip()] = value.strip()

    tools = [item.strip() for item in fm.get("tools", "").split(",") if item.strip()]
    return {
        "name": fm.get("name", Path(md_path).stem),
        "tools": tools,
        "model": fm.get("model") or None,
        "system_prompt": match.group(2).strip(),
    }


def render_prompt(template_path: Path, firmware_path: str, output_path: str) -> str:
    text = template_path.read_text()
    text = text.replace("$input", firmware_path)
    text = text.replace("$output", output_path)
    return text


def render_template(template_path: Path, replacements: dict[str, str]) -> str:
    text = template_path.read_text()
    for key, value in replacements.items():
        text = text.replace(key, value)
    return text
