"""Case/global vulnerability identity helpers."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4


def generate_global_vuln_id() -> str:
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return f"vuln-{ts}-{uuid4().hex[:10]}"
