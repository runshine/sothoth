#!/bin/bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-secflow-ns}"
DEFAULT_IMAGE_TAG="${DEFAULT_IMAGE_TAG:-latest}"
B2S_IMAGE_REPO="${B2S_IMAGE_REPO:-ghcr.io/runshine/secflow-app-binary-to-source}"
BIN_EVOLUTION_IMAGE_REPO="${BIN_EVOLUTION_IMAGE_REPO:-ghcr.io/runshine/secflow-app-binary-evolution-center}"
BIN_SECURITY_IMAGE_REPO="${BIN_SECURITY_IMAGE_REPO:-ghcr.io/runshine/secflow-app-binary-security}"
ENTRY_ANALYSE_IMAGE_REPO="${ENTRY_ANALYSE_IMAGE_REPO:-ghcr.io/runshine/secflow-app-entry-analyse}"
DATAFLOW_ANALYSE_IMAGE_REPO="${DATAFLOW_ANALYSE_IMAGE_REPO:-ghcr.io/runshine/secflow-app-dataflow-analyse}"
SYSTEM_ANALYSE_IMAGE_REPO="${SYSTEM_ANALYSE_IMAGE_REPO:-ghcr.io/runshine/secflow-app-system-analyse}"
FRONTEND_IMAGE_REPO="${FRONTEND_IMAGE_REPO:-ghcr.io/runshine/secflow-frontend}"
RESOURCE_IMAGE_REPO="${RESOURCE_IMAGE_REPO:-ghcr.io/runshine/secflow-platform-resource}"
GATEWAY_WORKER_IMAGE_REPO="${GATEWAY_WORKER_IMAGE_REPO:-ghcr.io/runshine/secflow-platform-resource-file-gateway-worker}"
FW_UNPACKER_IMAGE_REPO="${FW_UNPACKER_IMAGE_REPO:-ghcr.io/runshine/secflow-app-firmware-unpacker}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

B2S_MANAGER_DEPLOYMENT="secflow-app-binary-to-source-manager"
B2S_WORKER_DEPLOYMENT="secflow-app-binary-to-source-worker"
B2S_MANAGER_CONTAINER="secflow-app-binary-to-source-manager"
B2S_WORKER_CONTAINER="secflow-app-binary-to-source-worker"
BIN_EVOLUTION_MANAGER_DEPLOYMENT="secflow-app-binary-evolution-center-manager"
BIN_EVOLUTION_WORKER_DEPLOYMENT="secflow-app-binary-evolution-center-worker"
BIN_EVOLUTION_MANAGER_CONTAINER="secflow-app-binary-evolution-center-manager"
BIN_EVOLUTION_WORKER_CONTAINER="secflow-app-binary-evolution-center-worker"
BIN_SECURITY_API_DEPLOYMENT="secflow-app-binary-security"
BIN_SECURITY_WORKER_DEPLOYMENT="secflow-app-binary-security-worker"
BIN_SECURITY_REDUCER_DEPLOYMENT="secflow-app-binary-security-reducer"
ENTRY_ANALYSE_DEPLOYMENTS=(
  "secflow-app-entry-analyse:secflow-app-entry-analyse"
  "secflow-app-entry-analyse-scheduler:secflow-app-entry-analyse-scheduler"
  "secflow-app-entry-analyse-worker:secflow-app-entry-analyse-worker"
)
DATAFLOW_ANALYSE_DEPLOYMENTS=(
  "secflow-app-dataflow-analyse:secflow-app-dataflow-analyse"
  "secflow-app-dataflow-analyse-worker:secflow-app-dataflow-analyse"
)
SYSTEM_ANALYSE_DEPLOYMENTS=(
  "secflow-app-system-analyse:secflow-app-system-analyse"
  "secflow-app-system-analyse-worker:secflow-app-system-analyse-worker"
  "secflow-app-system-analyse-runner:secflow-app-system-analyse-runner"
)
FRONTEND_DEPLOYMENT="secflow-platform-frontend"
FRONTEND_CONTAINER="secflow-platform-frontend"

usage() {
  cat <<'HELP'
Usage:
  ./update_k8s_image_all.sh
  ./update_k8s_image_all.sh [global_tag]
  ./update_k8s_image_all.sh --tag <tag> [--b2s-image <image_or_tag>] [--binary-evolution-image <image_or_tag>] [--binary-security-image <image_or_tag>] [--entry-analyse-image <image_or_tag>] [--dataflow-analyse-image <image_or_tag>] [--system-analyse-image <image_or_tag>] [--frontend-image <image_or_tag>] [--resource-image <image_or_tag>] [--gateway-worker-image <image_or_tag>] [--firmware-unpacker-image <image_or_tag>]

Examples:
  ./update_k8s_image_all.sh
  ./update_k8s_image_all.sh latest
  ./update_k8s_image_all.sh --tag 20260508-abcdef0
  ./update_k8s_image_all.sh --binary-evolution-image 20260512-abcdef0
  ./update_k8s_image_all.sh --entry-analyse-image ghcr.io/runshine/secflow-app-entry-analyse:20260513
  ./update_k8s_image_all.sh --binary-security-image 20260513-af453b4
  ./update_k8s_image_all.sh --resource-image 20260403
  ./update_k8s_image_all.sh --gateway-worker-image ghcr.io/runshine/secflow-platform-resource-file-gateway-worker:20260403
  ./update_k8s_image_all.sh --firmware-unpacker-image 20260428

Behavior:
  - No args: update all secflow-* deployments in the namespace to :latest for managed repos.
  - global tag: update all secflow-* deployments in the namespace to the same tag for managed repos.
  - Always force rollout restart for secflow-* deployments, so unchanged tags such as :latest are pulled again.
  - Managed repos:
      ghcr.io/runshine/*
      runshine0819/secflow-*
  - b2s image: override binary-to-source manager/worker image.
  - binary-evolution image: override binary-evolution-center manager/worker image.
  - binary-security image: override binary-security api/worker image.
  - entry-analyse image: override entry-analyse api/scheduler/worker image.
  - dataflow-analyse image: override dataflow-analyse api/worker image.
  - system-analyse image: override system-analyse api/worker/runner image.
  - frontend image: override secflow platform frontend image.
  - resource image: override secflow-platform-resource image.
  - gateway-worker image: update file_gateway.worker_image in resource ConfigMap template vars.
  - firmware-unpacker image: override secflow-app-firmware-unpacker image.
  - Non-secflow deployments and third-party sidecars are skipped.
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

is_managed_repo() {
  local repo="${1:-}"
  [[ "${repo}" == ghcr.io/runshine/* || "${repo}" == runshine0819/secflow-* ]]
}

image_repo() {
  local image="${1:-}"
  local without_digest="${image%@*}"
  local tail="${without_digest##*/}"
  if [[ "${tail}" == *":"* ]]; then
    echo "${without_digest%:*}"
  else
    echo "${without_digest}"
  fi
}

resolve_target_image() {
  local current_image="${1:-}"
  local requested="${2:-}"
  if [[ -z "${requested}" ]]; then
    echo "${current_image}"
    return 0
  fi
  if [[ "${requested}" == *"/"* && "${requested}" == *":"* ]]; then
    echo "${requested}"
    return 0
  fi
  echo "$(image_repo "${current_image}"):${requested}"
}

image_exists() {
  local image="${1:-}"
  [[ -n "${image}" ]] || return 1

  if command -v docker >/dev/null 2>&1; then
    docker manifest inspect "${image}" >/dev/null 2>&1 && return 0
  fi

  if command -v crane >/dev/null 2>&1; then
    crane manifest "${image}" >/dev/null 2>&1 && return 0
  fi

  if command -v skopeo >/dev/null 2>&1; then
    skopeo inspect "docker://${image}" >/dev/null 2>&1 && return 0
  fi

  return 1
}

assert_image_exists() {
  local image="${1:-}"
  local source_label="${2:-image}"
  [[ -n "${image}" ]] || return 0

  if [[ -n "${VALIDATED_IMAGES[${image}]+x}" ]]; then
    return 0
  fi

  echo "[INFO] Validating ${source_label}: ${image}"
  if ! image_exists "${image}"; then
    echo "[ERROR] Image not found or registry metadata is unreachable: ${image}"
    echo "        Refusing to continue before mutating Kubernetes resources."
    echo "        Hint: confirm the image tag exists in GHCR, or pass an explicit image/tag that has been built."
    exit 1
  fi

  VALIDATED_IMAGES["${image}"]=1
}

update_deployment_container() {
  local deployment="${1:-}"
  local container="${2:-}"
  local current_image="${3:-}"
  local requested="${4:-}"
  local target_image
  target_image="$(resolve_target_image "${current_image}" "${requested}")"
  if [[ "${target_image}" == "${current_image}" ]]; then
    echo "[INFO] ${deployment}/${container} already uses ${current_image}"
    return 0
  fi
  assert_image_exists "${target_image}" "${deployment}/${container}"
  echo "[INFO] Updating ${deployment}/${container}"
  echo "       ${current_image} -> ${target_image}"
  kubectl -n "${NAMESPACE}" set image deployment/"${deployment}" "${container}"="${target_image}" >/dev/null
}

deployment_exists() {
  local deployment="${1:-}"
  kubectl -n "${NAMESPACE}" get deployment "${deployment}" >/dev/null 2>&1
}

maybe_set_explicit_image() {
  local deployment="${1:-}"
  local container="${2:-}"
  local target_image="${3:-}"
  [[ -n "${deployment}" && -n "${container}" && -n "${target_image}" ]] || return 0
  deployment_exists "${deployment}" || return 0
  local current_image
  current_image="$(kubectl -n "${NAMESPACE}" get deployment "${deployment}" -o jsonpath="{.spec.template.spec.containers[?(@.name=='${container}')].image}" 2>/dev/null || true)"
  [[ -n "${current_image}" ]] || return 0
  update_deployment_container "${deployment}" "${container}" "${current_image}" "${target_image}"
}

B2S_IMAGE_ARG=""
BIN_EVOLUTION_IMAGE_ARG=""
BIN_SECURITY_IMAGE_ARG=""
ENTRY_ANALYSE_IMAGE_ARG=""
DATAFLOW_ANALYSE_IMAGE_ARG=""
SYSTEM_ANALYSE_IMAGE_ARG=""
FRONTEND_IMAGE_ARG=""
RESOURCE_IMAGE_ARG=""
GATEWAY_WORKER_IMAGE_ARG=""
FW_UNPACKER_IMAGE_ARG=""
GLOBAL_TAG_ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --tag)
      GLOBAL_TAG_ARG="${2:-}"
      shift 2
      ;;
    --b2s-image)
      B2S_IMAGE_ARG="${2:-}"
      shift 2
      ;;
    --binary-evolution-image)
      BIN_EVOLUTION_IMAGE_ARG="${2:-}"
      shift 2
      ;;
    --binary-security-image)
      BIN_SECURITY_IMAGE_ARG="${2:-}"
      shift 2
      ;;
    --entry-analyse-image)
      ENTRY_ANALYSE_IMAGE_ARG="${2:-}"
      shift 2
      ;;
    --dataflow-analyse-image)
      DATAFLOW_ANALYSE_IMAGE_ARG="${2:-}"
      shift 2
      ;;
    --system-analyse-image)
      SYSTEM_ANALYSE_IMAGE_ARG="${2:-}"
      shift 2
      ;;
    --frontend-image)
      FRONTEND_IMAGE_ARG="${2:-}"
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
      if [[ -z "${GLOBAL_TAG_ARG}" ]]; then
        GLOBAL_TAG_ARG="$1"
        shift
      else
        echo "[ERROR] Unknown argument: $1"
        usage
        exit 1
      fi
      ;;
  esac
done

GLOBAL_TAG="${GLOBAL_TAG_ARG:-${DEFAULT_IMAGE_TAG}}"
B2S_IMAGE="$(resolve_image "${B2S_IMAGE_ARG}" "${B2S_IMAGE_REPO}")"
BIN_EVOLUTION_IMAGE="$(resolve_image "${BIN_EVOLUTION_IMAGE_ARG}" "${BIN_EVOLUTION_IMAGE_REPO}")"
BIN_SECURITY_IMAGE="$(resolve_image "${BIN_SECURITY_IMAGE_ARG}" "${BIN_SECURITY_IMAGE_REPO}")"
ENTRY_ANALYSE_IMAGE="$(resolve_image "${ENTRY_ANALYSE_IMAGE_ARG}" "${ENTRY_ANALYSE_IMAGE_REPO}")"
DATAFLOW_ANALYSE_IMAGE="$(resolve_image "${DATAFLOW_ANALYSE_IMAGE_ARG}" "${DATAFLOW_ANALYSE_IMAGE_REPO}")"
SYSTEM_ANALYSE_IMAGE="$(resolve_image "${SYSTEM_ANALYSE_IMAGE_ARG}" "${SYSTEM_ANALYSE_IMAGE_REPO}")"
FRONTEND_IMAGE="$(resolve_image "${FRONTEND_IMAGE_ARG}" "${FRONTEND_IMAGE_REPO}")"
RESOURCE_IMAGE="$(resolve_image "${RESOURCE_IMAGE_ARG}" "${RESOURCE_IMAGE_REPO}")"
GATEWAY_WORKER_IMAGE="$(resolve_image "${GATEWAY_WORKER_IMAGE_ARG}" "${GATEWAY_WORKER_IMAGE_REPO}")"
FW_UNPACKER_IMAGE="$(resolve_image "${FW_UNPACKER_IMAGE_ARG}" "${FW_UNPACKER_IMAGE_REPO}")"

declare -A VALIDATED_IMAGES=()

if [[ -f "${SCRIPT_DIR}/images.env" ]]; then
  # shellcheck disable=SC1091
  source "${SCRIPT_DIR}/images.env"
fi

if [[ -n "${RESOURCE_IMAGE}" || -n "${GATEWAY_WORKER_IMAGE}" ]]; then
  export SECFLOW_PLATFORM_RESOURCE_IMAGE="${RESOURCE_IMAGE:-${SECFLOW_PLATFORM_RESOURCE_IMAGE:-${RESOURCE_IMAGE_REPO}:${GLOBAL_TAG}}}"
  export SECFLOW_PLATFORM_RESOURCE_FILE_GATEWAY_WORKER_IMAGE="${GATEWAY_WORKER_IMAGE:-${SECFLOW_PLATFORM_RESOURCE_FILE_GATEWAY_WORKER_IMAGE:-${GATEWAY_WORKER_IMAGE_REPO}:${GLOBAL_TAG}}}"

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

for pair in "${ENTRY_ANALYSE_DEPLOYMENTS[@]}"; do
  maybe_set_explicit_image "${pair%%:*}" "${pair##*:}" "${ENTRY_ANALYSE_IMAGE}"
done

for pair in "${DATAFLOW_ANALYSE_DEPLOYMENTS[@]}"; do
  maybe_set_explicit_image "${pair%%:*}" "${pair##*:}" "${DATAFLOW_ANALYSE_IMAGE}"
done

for pair in "${SYSTEM_ANALYSE_DEPLOYMENTS[@]}"; do
  maybe_set_explicit_image "${pair%%:*}" "${pair##*:}" "${SYSTEM_ANALYSE_IMAGE}"
done

maybe_set_explicit_image "${BIN_SECURITY_API_DEPLOYMENT}" "secflow-app-binary-security" "${BIN_SECURITY_IMAGE}"
maybe_set_explicit_image "${BIN_SECURITY_WORKER_DEPLOYMENT}" "secflow-app-binary-security-worker" "${BIN_SECURITY_IMAGE}"
maybe_set_explicit_image "${BIN_SECURITY_REDUCER_DEPLOYMENT}" "secflow-app-binary-security-reducer" "${BIN_SECURITY_IMAGE}"
maybe_set_explicit_image "${FRONTEND_DEPLOYMENT}" "${FRONTEND_CONTAINER}" "${FRONTEND_IMAGE}"
maybe_set_explicit_image "${B2S_MANAGER_DEPLOYMENT}" "${B2S_MANAGER_CONTAINER}" "${B2S_IMAGE}"
maybe_set_explicit_image "${B2S_WORKER_DEPLOYMENT}" "${B2S_WORKER_CONTAINER}" "${B2S_IMAGE}"
maybe_set_explicit_image "${BIN_EVOLUTION_MANAGER_DEPLOYMENT}" "${BIN_EVOLUTION_MANAGER_CONTAINER}" "${BIN_EVOLUTION_IMAGE}"
maybe_set_explicit_image "${BIN_EVOLUTION_WORKER_DEPLOYMENT}" "${BIN_EVOLUTION_WORKER_CONTAINER}" "${BIN_EVOLUTION_IMAGE}"
maybe_set_explicit_image "secflow-app-firmware-unpacker-api" "secflow-app-firmware-unpacker" "${FW_UNPACKER_IMAGE}"
maybe_set_explicit_image "secflow-app-firmware-unpacker-dispatcher" "secflow-app-firmware-unpacker" "${FW_UNPACKER_IMAGE}"
maybe_set_explicit_image "secflow-app-firmware-unpacker-cleanup" "secflow-app-firmware-unpacker" "${FW_UNPACKER_IMAGE}"

echo "[INFO] Scanning deployments in namespace: ${NAMESPACE}"
while IFS=$'\t' read -r deployment containers; do
  [[ -n "${deployment}" ]] || continue
  [[ "${deployment}" == secflow-* ]] || continue
  IFS=';' read -ra pairs <<< "${containers}"
  for pair in "${pairs[@]}"; do
    [[ -n "${pair}" ]] || continue
    container="${pair%%=*}"
    current_image="${pair#*=}"
    repo="$(image_repo "${current_image}")"
    if ! is_managed_repo "${repo}"; then
      continue
    fi
    requested_tag="${GLOBAL_TAG}"
    case "${deployment}:${container}" in
      "${B2S_MANAGER_DEPLOYMENT}:${B2S_MANAGER_CONTAINER}"|"${B2S_WORKER_DEPLOYMENT}:${B2S_WORKER_CONTAINER}")
        [[ -n "${B2S_IMAGE}" ]] && requested_tag="${B2S_IMAGE}"
        ;;
      "${BIN_EVOLUTION_MANAGER_DEPLOYMENT}:${BIN_EVOLUTION_MANAGER_CONTAINER}"|"${BIN_EVOLUTION_WORKER_DEPLOYMENT}:${BIN_EVOLUTION_WORKER_CONTAINER}")
        [[ -n "${BIN_EVOLUTION_IMAGE}" ]] && requested_tag="${BIN_EVOLUTION_IMAGE}"
        ;;
      "${BIN_SECURITY_API_DEPLOYMENT}:secflow-app-binary-security"|"${BIN_SECURITY_WORKER_DEPLOYMENT}:secflow-app-binary-security-worker"|"${BIN_SECURITY_REDUCER_DEPLOYMENT}:secflow-app-binary-security-reducer")
        [[ -n "${BIN_SECURITY_IMAGE}" ]] && requested_tag="${BIN_SECURITY_IMAGE}"
        ;;
      "secflow-app-entry-analyse:secflow-app-entry-analyse"|"secflow-app-entry-analyse-scheduler:secflow-app-entry-analyse-scheduler"|"secflow-app-entry-analyse-worker:secflow-app-entry-analyse-worker")
        [[ -n "${ENTRY_ANALYSE_IMAGE}" ]] && requested_tag="${ENTRY_ANALYSE_IMAGE}"
        ;;
      "secflow-app-dataflow-analyse:secflow-app-dataflow-analyse"|"secflow-app-dataflow-analyse-worker:secflow-app-dataflow-analyse")
        [[ -n "${DATAFLOW_ANALYSE_IMAGE}" ]] && requested_tag="${DATAFLOW_ANALYSE_IMAGE}"
        ;;
      "secflow-app-system-analyse:secflow-app-system-analyse"|"secflow-app-system-analyse-worker:secflow-app-system-analyse-worker"|"secflow-app-system-analyse-runner:secflow-app-system-analyse-runner")
        [[ -n "${SYSTEM_ANALYSE_IMAGE}" ]] && requested_tag="${SYSTEM_ANALYSE_IMAGE}"
        ;;
      "${FRONTEND_DEPLOYMENT}:${FRONTEND_CONTAINER}")
        [[ -n "${FRONTEND_IMAGE}" ]] && requested_tag="${FRONTEND_IMAGE}"
        ;;
      "secflow-platform-resource:secflow-platform-resource")
        [[ -n "${RESOURCE_IMAGE}" ]] && requested_tag="${RESOURCE_IMAGE}"
        ;;
      "secflow-app-firmware-unpacker-api:secflow-app-firmware-unpacker"|"secflow-app-firmware-unpacker-dispatcher:secflow-app-firmware-unpacker"|"secflow-app-firmware-unpacker-cleanup:secflow-app-firmware-unpacker")
        [[ -n "${FW_UNPACKER_IMAGE}" ]] && requested_tag="${FW_UNPACKER_IMAGE}"
        ;;
    esac
    update_deployment_container "${deployment}" "${container}" "${current_image}" "${requested_tag}"
  done
done < <(
  kubectl -n "${NAMESPACE}" get deploy \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .spec.template.spec.containers[*]}{.name}{"="}{.image}{";"}{end}{"\n"}{end}'
)

echo "[INFO] Forcing rollout restart for secflow deployments"
while IFS= read -r deployment; do
  [[ -n "${deployment}" ]] || continue
  kubectl -n "${NAMESPACE}" rollout restart "deployment/${deployment}"
done < <(
  kubectl -n "${NAMESPACE}" get deploy -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep '^secflow-'
)

echo "[INFO] Waiting for secflow deployments to finish rollout"
while IFS= read -r deployment; do
  [[ -n "${deployment}" ]] || continue
  kubectl -n "${NAMESPACE}" rollout status "deployment/${deployment}" --timeout=300s
done < <(
  kubectl -n "${NAMESPACE}" get deploy -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep '^secflow-'
)

echo "[INFO] Done"
