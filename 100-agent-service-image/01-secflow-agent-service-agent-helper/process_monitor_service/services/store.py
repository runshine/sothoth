from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any


class JsonStateStore:
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def load(self, default: Any) -> Any:
        with self._lock:
            if not self._path.exists():
                return default
            try:
                return json.loads(self._path.read_text())
            except Exception:
                return default

    def save(self, payload: Any) -> None:
        with self._lock:
            tmp = self._path.with_suffix(self._path.suffix + '.tmp')
            tmp.write_text(json.dumps(payload, ensure_ascii=True, indent=2))
            os.replace(tmp, self._path)
