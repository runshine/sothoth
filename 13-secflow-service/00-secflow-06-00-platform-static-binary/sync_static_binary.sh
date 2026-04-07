#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOWNLOAD_DIR="${SCRIPT_DIR}/downloads"
PYTHON_BIN="${PYTHON_BIN:-python3}"
CONDA_BIN="${CONDA_BIN:-/home/runshine/miniconda3/bin/conda}"

if [ -x "${CONDA_BIN}" ]; then
  eval "$("${CONDA_BIN}" shell.bash hook)"
  conda activate sothoth >/dev/null 2>&1 || true
  PYTHON_BIN="python"
fi

cd "${SCRIPT_DIR}"

"${PYTHON_BIN}" -m pip install requests tqdm requests_toolbelt
"${PYTHON_BIN}" download_from_github_release.py https://github.com/runshine/static_binary_tools/releases/tag/v1.0 "${DOWNLOAD_DIR}"
"${PYTHON_BIN}" upload_to_static_binary_service.py --folder "${DOWNLOAD_DIR}" --url https://secflow.ai.icsl.huawei.com:443 --workers 1 --retries 1
