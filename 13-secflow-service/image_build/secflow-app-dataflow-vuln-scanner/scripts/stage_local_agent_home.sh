#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOCAL_HOME="${LOCAL_HOME:-$HOME}"
STAGE_ROOT="${STAGE_ROOT:-${SERVICE_ROOT}/.docker-runtime-home}"

copy_home_dir() {
  local src_name="$1"
  shift

  local src_dir="${LOCAL_HOME}/${src_name}"
  local dest_dir="${STAGE_ROOT}/root/${src_name}"
  local -a exclude_args=()
  local pattern

  if [ ! -d "$src_dir" ]; then
    echo "[stage] skip ${src_dir} (not found)"
    return 0
  fi

  for pattern in "$@"; do
    exclude_args+=(--exclude="$pattern")
  done

  rm -rf "$dest_dir"
  mkdir -p "${STAGE_ROOT}/root"

  tar -C "$LOCAL_HOME" "${exclude_args[@]}" -cf - "$src_name" | tar -C "${STAGE_ROOT}/root" -xf -
  echo "[stage] copied ${src_dir} -> ${dest_dir}"
}

mkdir -p "$STAGE_ROOT"
touch "${STAGE_ROOT}/.gitkeep"

copy_home_dir ".pi" \
  ".pi/agent/bin" \
  ".pi/agent/sessions" \
  ".pi/agent/logs" \
  ".pi/agent/tmp"

copy_home_dir ".copilot"

echo "[stage] build context prepared under ${STAGE_ROOT}"
find "${STAGE_ROOT}" -maxdepth 5 -type f | sort
