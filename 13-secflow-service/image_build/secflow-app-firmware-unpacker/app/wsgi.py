#!/usr/bin/env python3
"""WSGI entrypoint for running the FastAPI app behind Gunicorn threads."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from a2wsgi import ASGIMiddleware


PROJECT_ROOT = Path(__file__).parent.parent

os.environ["PYTHONPATH"] = str(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "app"))

from app.main import app as asgi_app


app = ASGIMiddleware(asgi_app)
