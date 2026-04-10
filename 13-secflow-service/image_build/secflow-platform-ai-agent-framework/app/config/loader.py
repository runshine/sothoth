from __future__ import annotations

import json
from pathlib import Path

from app.models.config_models import FrameworkConfig


def load_framework_config(path: str | Path) -> FrameworkConfig:
    config_path = Path(path)
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    return FrameworkConfig.model_validate(payload)
