#!/bin/bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-secflow-ns}"
B2S_IMAGE_REPO="${B2S_IMAGE_REPO:-ghcr.io/runshine/secflow-app-binary-to-source}"
RESOURCE_IMAGE_REPO="${RESOURCE_IMAGE_REPO:-ghcr.io/runshine/secflow-platform-resource}"
GATEWAY_WORKER_IMAGE_REPO="${GATEWAY_WORKER_IMAGE_REPO:-ghcr.io/runshine/secflow-platform-resource-file-gateway-worker}"
FW_UNPACKER_IMAGE_REPO="${FW_UNPACKER_IMAGE_REPO:-ghcr.io/runshine/secflow-app-firmware-unpacker}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

B2S_MANAGER_DEPLOYMENT="secflow-app-binary-to-source-manager"
B2S_WORKER_DEPLOYMENT="secflow-app-binary-to-source-worker"
B2S_MANAGER_CONTAINER="secflow-app-binary-to-source-manager"
B2S_WORKER_CONTAINER="secflow-app-binary-to-source-worker"
RESOURCE_DEPLOYMENT="secflow-platform-resource"
RESOURCE_CONTAINER="secflow-platform-resource"
FW_UNPACKER_DEPLOYMENT="secflow-app-firmware-unpacker"
FW_UNPACKER_CONTAINER="secflow-app-firmware-unpacker"

usage() {
  cat <<'HELP'
Usage:
  ./update_k8s_image_all.sh [binary_to_source_image_or_tag]
  ./update_k8s_image_all.sh --b2s-image <image_or_tag> --resource-image <image_or_tag> --gateway-worker-image <image_or_tag> --firmware-unpacker-image <image_or_tag>

Examples:
  ./update_k8s_image_all.sh
  ./update_k8s_image_all.sh latest
  ./update_k8s_image_all.sh --resource-image 20260403
  ./update_k8s_image_all.sh --gateway-worker-image ghcr.io/runshine/secflow-platform-resource-file-gateway-worker:20260403
  ./update_k8s_image_all.sh --firmware-unpacker-image 20260428

Behavior:
  - No args: only rollout restart all deployments.
  - b2s image: update binary-to-source manager/worker image.
  - resource image: update secflow-platform-resource image.
  - gateway-worker image: update file_gateway.worker_image in resource ConfigMap template vars.
  - firmware-unpacker image: update secflow-app-firmware-unpacker deployment image.
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
FW_UNPACKER_IMAGE_ARG=""

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
    --firmware-unpacker-image)
      FW_UNPACKER_IMAGE_ARG="${2:-}"
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
FW_UNPACKER_IMAGE="$(resolve_image "${FW_UNPACKER_IMAGE_ARG}" "${FW_UNPACKER_IMAGE_REPO}")"

if [[ -f "${SCRIPT_DIR}/images.env" ]]; then
  # shellcheck disable=SC1091
  source "${SCRIPT_DIR}/images.env"
fi

if [[ -n "${B2S_IMAGE}" ]]; then
  echo "[INFO] Updating binary-to-source image to: ${B2S_IMAGE}"
  kubectl -n "${NAMESPACE}" set image deployment/"${B2S_MANAGER_DEPLOYMENT}" \
    "${B2S_MANAGER_CONTAINER}"="${B2S_IMAGE}"
  kubectl -n "${NAMESPACE}" set image deployment/"${B2S_WORKER_DEPLOYMENT}" \
    "${B2S_WORKER_CONTAINER}"="${B2S_IMAGE}"
fi

if [[ -n "${RESOURCE_IMAGE}" || -n "${GATEWAY_WORKER_IMAGE}" ]]; then
  export SECFLOW_PLATFORM_RESOURCE_IMAGE="${RESOURCE_IMAGE:-${SECFLOW_PLATFORM_RESOURCE_IMAGE:-${RESOURCE_IMAGE_REPO}:latest}}"
  export SECFLOW_PLATFORM_RESOURCE_FILE_GATEWAY_WORKER_IMAGE="${GATEWAY_WORKER_IMAGE:-${SECFLOW_PLATFORM_RESOURCE_FILE_GATEWAY_WORKER_IMAGE:-${GATEWAY_WORKER_IMAGE_REPO}:latest}}"

  echo "[INFO] Applying resource ConfigMap with image vars:"
  echo "       SECFLOW_PLATFORM_RESOURCE_IMAGE=${SECFLOW_PLATFORM_RESOURCE_IMAGE}"
  echo "       SECFLOW_PLATFORM_RESOURCE_FILE_GATEWAY_WORKER_IMAGE=${SECFLOW_PLATFORM_RESOURCE_FILE_GATEWAY_WORKER_IMAGE}"

  if ! command -v envsubst >/dev/null 2>&1; then
    echo "[ERROR] envsubst is required to render resource image templates."
    echo "        Please install gettext and retry."
    exit 1
  fi

  envsubst < "${SCRIPT_DIR}/00-secflow-05-00-platform-resource-configmap.yaml" | kubectl apply -f -
  envsubst < "${SCRIPT_DIR}/00-secflow-05-03-platform-resource-deployment.yaml" | kubectl apply -f -
fi

if [[ -n "${FW_UNPACKER_IMAGE}" ]]; then
  echo "[INFO] Updating firmware-unpacker image to: ${FW_UNPACKER_IMAGE}"
  kubectl -n "${NAMESPACE}" set image deployment/"${FW_UNPACKER_DEPLOYMENT}" \
    "${FW_UNPACKER_CONTAINER}"="${FW_UNPACKER_IMAGE}"
fi

echo "[INFO] Restarting all deployments in namespace: ${NAMESPACE}"
kubectl rollout restart deployment -n "${NAMESPACE}"
