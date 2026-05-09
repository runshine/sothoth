"""Firmware feature extraction used by the feature_match stage."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from app.pipeline_stages.s01_preprocess.engine import detect_format


def extract_firmware_features(firmware_path: str) -> dict:
    path = Path(firmware_path)
    info = detect_format(firmware_path)
    features = {
        "filename": path.name,
        "ext": info["ext"],
        "ext2": info["ext2"],
        "fmt": info["fmt"] or "unknown",
        "size": 0,
        "magic_hex": info["magic"].hex()[:8] if info["magic"] else "",
        "binwalk_sigs": [],
    }
    try:
        features["size"] = os.path.getsize(firmware_path)
    except Exception:
        pass
    try:
        proc = subprocess.run(
            ["binwalk", "-B", firmware_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("DECIMAL") and not line.startswith("-"):
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    features["binwalk_sigs"].append(parts[2][:100].lower())
    except Exception:
        pass
    return features
