#!/bin/bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-secflow-ns}"
B2S_IMAGE_REPO="${B2S_IMAGE_REPO:-ghcr.io/runshine/secflow-app-binary-to-source}"
B2S_MANAGER_DEPLOYMENT="secflow-app-binary-to-source-manager"
B2S_WORKER_DEPLOYMENT="secflow-app-binary-to-source-worker"
B2S_MANAGER_CONTAINER="secflow-app-binary-to-source-manager"
B2S_WORKER_CONTAINER="secflow-app-binary-to-source-worker"

usage() {
  cat <<'EOF'
Usage:
  ./update_k8s_image_all.sh [binary_to_source_image_or_tag]

Examples:
  ./update_k8s_image_all.sh
  ./update_k8s_image_all.sh latest
  ./update_k8s_image_all.sh 2026.04.03
  ./update_k8s_image_all.sh ghcr.io/runshine/secflow-app-binary-to-source:2026.04.03

Behavior:
  - No argument: only rollout restart all deployments (existing behavior).
  - With argument: update binary-to-source manager/worker image first, then rollout restart all deployments.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

resolve_b2s_image() {
  local input="${1:-}"
  if [[ -z "${input}" ]]; then
    echo ""
    return 0
  fi
  if [[ "${input}" == *"/"* && "${input}" == *":"* ]]; then
    echo "${input}"
    return 0
  fi
  echo "${B2S_IMAGE_REPO}:${input}"
}

B2S_IMAGE="$(resolve_b2s_image "${1:-}")"
if [[ -n "${B2S_IMAGE}" ]]; then
  echo "[INFO] Updating binary-to-source image to: ${B2S_IMAGE}"
  kubectl -n "${NAMESPACE}" set image deployment/"${B2S_MANAGER_DEPLOYMENT}" \
    "${B2S_MANAGER_CONTAINER}"="${B2S_IMAGE}"
  kubectl -n "${NAMESPACE}" set image deployment/"${B2S_WORKER_DEPLOYMENT}" \
    "${B2S_WORKER_CONTAINER}"="${B2S_IMAGE}"
fi

kubectl rollout restart deployment/secflow-app-code-server -n "${NAMESPACE}"
kubectl rollout restart deployment/secflow-app-secmate-ng -n "${NAMESPACE}"
kubectl rollout restart deployment/"${B2S_MANAGER_DEPLOYMENT}" -n "${NAMESPACE}"
kubectl rollout restart deployment/"${B2S_WORKER_DEPLOYMENT}" -n "${NAMESPACE}"
kubectl rollout restart deployment/secflow-platform-agent -n "${NAMESPACE}"
kubectl rollout restart deployment/secflow-platform-auth -n "${NAMESPACE}"
kubectl rollout restart deployment/secflow-platform-deploy-script -n "${NAMESPACE}"
kubectl rollout restart deployment/secflow-platform-frontend -n "${NAMESPACE}"
kubectl rollout restart deployment/secflow-platform-k8s -n "${NAMESPACE}"
kubectl rollout restart deployment/secflow-platform-menu -n "${NAMESPACE}"
kubectl rollout restart deployment/secflow-platform-fileserver -n "${NAMESPACE}"
kubectl rollout restart deployment/secflow-platform-project -n "${NAMESPACE}"
kubectl rollout restart deployment/secflow-platform-resource -n "${NAMESPACE}"
kubectl rollout restart deployment/secflow-platform-static-binary -n "${NAMESPACE}"
kubectl rollout restart deployment/secflow-platform-system-analysis -n "${NAMESPACE}"
kubectl rollout restart deployment/secflow-platform-workflow -n "${NAMESPACE}"
kubectl rollout restart deployment/secflow-platform-source-manager -n "${NAMESPACE}"
kubectl rollout restart deployment/secflow-platform-source-worker -n "${NAMESPACE}"
