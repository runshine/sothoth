#!/bin/bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-secflow-ns}"
B2S_IMAGE_REPO="${B2S_IMAGE_REPO:-ghcr.io/runshine/secflow-app-binary-to-source}"
RESOURCE_IMAGE_REPO="${RESOURCE_IMAGE_REPO:-ghcr.io/runshine/secflow-platform-resource}"
GATEWAY_WORKER_IMAGE_REPO="${GATEWAY_WORKER_IMAGE_REPO:-ghcr.io/runshine/secflow-platform-resource-file-gateway-worker}"

B2S_MANAGER_DEPLOYMENT="secflow-app-binary-to-source-manager"
B2S_WORKER_DEPLOYMENT="secflow-app-binary-to-source-worker"
B2S_MANAGER_CONTAINER="secflow-app-binary-to-source-manager"
B2S_WORKER_CONTAINER="secflow-app-binary-to-source-worker"
RESOURCE_DEPLOYMENT="secflow-platform-resource"
RESOURCE_CONTAINER="secflow-platform-resource"

usage() {
  cat <<'HELP'
Usage:
  ./update_k8s_image_all.sh [binary_to_source_image_or_tag]
  ./update_k8s_image_all.sh --b2s-image <image_or_tag> --resource-image <image_or_tag> --gateway-worker-image <image_or_tag>

Examples:
  ./update_k8s_image_all.sh
  ./update_k8s_image_all.sh latest
  ./update_k8s_image_all.sh --resource-image 20260403
  ./update_k8s_image_all.sh --gateway-worker-image ghcr.io/runshine/secflow-platform-resource-file-gateway-worker:20260403

Behavior:
  - No args: only rollout restart all deployments.
  - b2s image: update binary-to-source manager/worker image.
  - resource image: update secflow-platform-resource image.
  - gateway-worker image: set FILE_GATEWAY_WORKER_IMAGE env on secflow-platform-resource.
HELP
}

resolve_image() {
  local input="${1:-}"
  local default_repo="${2:-}"
  if [[ -z "${input}" ]]; then
    echo ""
    return 0
  fi
  if [[ "${input}" == *"/"* && "${input}" == *":"* ]]; then
    echo "${input}"
    return 0
  fi
  echo "${default_repo}:${input}"
}

B2S_IMAGE_ARG=""
RESOURCE_IMAGE_ARG=""
GATEWAY_WORKER_IMAGE_ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --b2s-image)
      B2S_IMAGE_ARG="${2:-}"
      shift 2
      ;;
    --resource-image)
      RESOURCE_IMAGE_ARG="${2:-}"
      shift 2
      ;;
    --gateway-worker-image)
      GATEWAY_WORKER_IMAGE_ARG="${2:-}"
      shift 2
      ;;
    *)
      if [[ -z "${B2S_IMAGE_ARG}" ]]; then
        B2S_IMAGE_ARG="$1"
        shift
      else
        echo "[ERROR] Unknown argument: $1"
        usage
        exit 1
      fi
      ;;
  esac
done

B2S_IMAGE="$(resolve_image "${B2S_IMAGE_ARG}" "${B2S_IMAGE_REPO}")"
RESOURCE_IMAGE="$(resolve_image "${RESOURCE_IMAGE_ARG}" "${RESOURCE_IMAGE_REPO}")"
GATEWAY_WORKER_IMAGE="$(resolve_image "${GATEWAY_WORKER_IMAGE_ARG}" "${GATEWAY_WORKER_IMAGE_REPO}")"

if [[ -n "${B2S_IMAGE}" ]]; then
  echo "[INFO] Updating binary-to-source image to: ${B2S_IMAGE}"
  kubectl -n "${NAMESPACE}" set image deployment/"${B2S_MANAGER_DEPLOYMENT}" \
    "${B2S_MANAGER_CONTAINER}"="${B2S_IMAGE}"
  kubectl -n "${NAMESPACE}" set image deployment/"${B2S_WORKER_DEPLOYMENT}" \
    "${B2S_WORKER_CONTAINER}"="${B2S_IMAGE}"
fi

if [[ -n "${RESOURCE_IMAGE}" ]]; then
  echo "[INFO] Updating resource service image to: ${RESOURCE_IMAGE}"
  kubectl -n "${NAMESPACE}" set image deployment/"${RESOURCE_DEPLOYMENT}" \
    "${RESOURCE_CONTAINER}"="${RESOURCE_IMAGE}"
fi

if [[ -n "${GATEWAY_WORKER_IMAGE}" ]]; then
  echo "[INFO] Setting FILE_GATEWAY_WORKER_IMAGE to: ${GATEWAY_WORKER_IMAGE}"
  kubectl -n "${NAMESPACE}" set env deployment/"${RESOURCE_DEPLOYMENT}" \
    FILE_GATEWAY_WORKER_IMAGE="${GATEWAY_WORKER_IMAGE}"
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
