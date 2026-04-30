#!/usr/bin/env python3
"""Startup script — sets PYTHONPATH and launches uvicorn."""

import os
import sys
from pathlib import Path

# Project root is the parent of this app/ directory
PROJECT_ROOT = Path(__file__).parent.parent

# Make both project root and app dir available for imports
os.environ["PYTHONPATH"] = str(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "app"))

import uvicorn
from app.config import get_config

if __name__ == "__main__":
    config = get_config()
    uvicorn.run(
        "app.main:app",
        host=config.app.host,
        port=config.app.port,
        reload=config.app.debug,
    )
