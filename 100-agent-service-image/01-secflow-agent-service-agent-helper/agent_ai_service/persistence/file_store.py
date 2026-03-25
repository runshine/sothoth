import json
import threading
from pathlib import Path
from typing import Any, Dict


class JsonFileStore:
    def __init__(self, path: Path, default_factory):
        self.path = path
        self.default_factory = default_factory
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def read(self) -> Dict[str, Any]:
        with self._lock:
            if not self.path.exists():
                return self.default_factory()
            try:
                return json.loads(self.path.read_text(encoding='utf-8'))
            except Exception:
                return self.default_factory()

    def write(self, data: Dict[str, Any]) -> None:
        with self._lock:
            temp = self.path.with_suffix(self.path.suffix + '.tmp')
            temp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
            temp.replace(self.path)
