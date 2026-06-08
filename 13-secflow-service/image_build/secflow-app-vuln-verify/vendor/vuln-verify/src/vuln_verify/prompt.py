from __future__ import annotations

from pathlib import Path


def load_prompt(threat_path: str) -> str:
    """加载 verifier 提示词模板，用威胁模型内容替换 {{THREAT_MODEL}}。"""
    template_dir = Path(__file__).parent.parent.parent / "templates"
    template = (template_dir / "verifier_prompt.md").read_text(encoding="utf-8")
    threat = Path(threat_path).read_text(encoding="utf-8")
    return template.replace("{{THREAT_MODEL}}", threat)
