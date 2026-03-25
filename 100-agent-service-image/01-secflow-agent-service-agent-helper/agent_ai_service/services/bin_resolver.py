from __future__ import annotations

import os
import shutil
from pathlib import Path


def resolve_binary(binary_name: str) -> str | None:
    direct = shutil.which(binary_name)
    if direct:
        return direct

    home = Path(os.path.expanduser("~"))
    candidates = [
        home / ".local" / "bin" / binary_name,
        Path("/usr/local/bin") / binary_name,
    ]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

    nvm_dir = Path(os.environ.get("NVM_DIR", str(home / ".nvm")))
    versions_dir = nvm_dir / "versions" / "node"
    if versions_dir.is_dir():
        matches = sorted(versions_dir.glob(f"*/bin/{binary_name}"))
        for match in reversed(matches):
            if match.is_file() and os.access(match, os.X_OK):
                return str(match)

    local_lib = home / ".local" / "lib"
    if local_lib.is_dir():
        matches = sorted(local_lib.glob(f"**/bin/{binary_name}"))
        for match in reversed(matches):
            if match.is_file() and os.access(match, os.X_OK):
                return str(match)

    return None


def binary_installed(binary_name: str) -> bool:
    return resolve_binary(binary_name) is not None
