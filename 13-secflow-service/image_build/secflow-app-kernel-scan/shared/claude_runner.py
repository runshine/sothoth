import json
import subprocess
from typing import Optional


def run_claude(
    prompt: str,
    model: str = "zai-org/GLM-5",
    timeout: Optional[int] = None,
    dangerously_skip_permissions: bool = True,
) -> tuple[str, bool]:
    cmd = ["claude"]
    if dangerously_skip_permissions:
        cmd.append("--dangerously-skip-permissions")
    cmd.extend(["--model", model, "-p", prompt])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return "", False
    except FileNotFoundError:
        return "claude CLI not found", False

    if proc.returncode != 0:
        return proc.stdout or proc.stderr, False
    return proc.stdout, True


def parse_json_response(response: str) -> Optional[dict]:
    text = response.strip()
    start = text.find("{")
    end = text.rfind("}") + 1
    if start == -1 or end == 0:
        return None
    try:
        return json.loads(text[start:end])
    except json.JSONDecodeError:
        return None
