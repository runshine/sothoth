#!/usr/bin/env bash
set -euo pipefail

LOCAL_HOME="${LOCAL_HOME:-$HOME}"
NAMESPACE="${NAMESPACE:-secflow-ns}"
SECRET_NAME="${SECRET_NAME:-secflow-app-dataflow-vuln-scanner-runtime-home}"
DEPLOYMENT_NAME="${DEPLOYMENT_NAME:-secflow-app-dataflow-vuln-scanner}"
RESTART_DEPLOYMENT="${RESTART_DEPLOYMENT:-1}"
WAIT_FOR_ROLLOUT="${WAIT_FOR_ROLLOUT:-1}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

package_home_dir() {
  local src_name="$1"
  local output_name="$2"
  shift 2

  local src_dir="${LOCAL_HOME}/${src_name}"
  local output_path="${TMP_DIR}/${output_name}"
  local -a exclude_args=()
  local pattern

  if [ ! -d "$src_dir" ]; then
    echo "[secret] skip ${src_dir} (not found)"
    return 1
  fi

  for pattern in "$@"; do
    exclude_args+=(--exclude="$pattern")
  done

  tar -C "$LOCAL_HOME" "${exclude_args[@]}" -czf "$output_path" "$src_name"
  echo "[secret] packaged ${src_dir} -> ${output_path}"
  return 0
}

package_home_dir ".pi" "pi-home.tar.gz" \
  ".pi/agent/bin" \
  ".pi/agent/sessions" \
  ".pi/agent/logs" \
  ".pi/agent/tmp"

secret_args=(--from-file="pi-home.tar.gz=${TMP_DIR}/pi-home.tar.gz")

if package_home_dir ".copilot" "copilot-home.tar.gz"; then
  secret_args+=(--from-file="copilot-home.tar.gz=${TMP_DIR}/copilot-home.tar.gz")
fi

kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME" \
  "${secret_args[@]}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "[secret] applied ${SECRET_NAME} in namespace ${NAMESPACE}"
du -h "${TMP_DIR}"/pi-home.tar.gz "${TMP_DIR}"/copilot-home.tar.gz 2>/dev/null || true

if [ "$RESTART_DEPLOYMENT" = "1" ]; then
  kubectl -n "$NAMESPACE" rollout restart deployment "$DEPLOYMENT_NAME"
  if [ "$WAIT_FOR_ROLLOUT" = "1" ]; then
    kubectl -n "$NAMESPACE" rollout status deployment "$DEPLOYMENT_NAME"
  fi
fi
