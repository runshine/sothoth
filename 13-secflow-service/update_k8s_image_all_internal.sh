#!/bin/bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-secflow-ns}"
DEFAULT_IMAGE_TAG="${DEFAULT_IMAGE_TAG:-latest}"
B2S_IMAGE_REPO="${B2S_IMAGE_REPO:-ghcr.io/runshine/secflow-app-binary-to-source}"
BIN_EVOLUTION_IMAGE_REPO="${BIN_EVOLUTION_IMAGE_REPO:-ghcr.io/runshine/secflow-app-binary-evolution-center}"
BIN_SECURITY_IMAGE_REPO="${BIN_SECURITY_IMAGE_REPO:-ghcr.io/runshine/secflow-app-binary-security}"
ENTRY_ANALYSE_IMAGE_REPO="${ENTRY_ANALYSE_IMAGE_REPO:-ghcr.io/runshine/secflow-app-entry-analyse}"
SYSTEM_ANALYSE_IMAGE_REPO="${SYSTEM_ANALYSE_IMAGE_REPO:-ghcr.io/runshine/secflow-app-system-analyse}"
FRONTEND_IMAGE_REPO="${FRONTEND_IMAGE_REPO:-ghcr.io/gaiasechw/chimera-frontend}"
RESOURCE_IMAGE_REPO="${RESOURCE_IMAGE_REPO:-ghcr.io/runshine/secflow-platform-resource}"
GATEWAY_WORKER_IMAGE_REPO="${GATEWAY_WORKER_IMAGE_REPO:-ghcr.io/runshine/secflow-platform-resource-file-gateway-worker}"
FW_UNPACKER_IMAGE_REPO="${FW_UNPACKER_IMAGE_REPO:-ghcr.io/runshine/secflow-app-firmware-unpacker}"
CHIRMERA_SCHEDULE_IMAGE_REPO="${CHIRMERA_SCHEDULE_IMAGE_REPO:-ghcr.io/runshine/chirmera-platform-schedule}"
ENTRY_ANALYSE_WORKER_REPLICAS="${ENTRY_ANALYSE_WORKER_REPLICAS:-4}"
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
ENTRY_ANALYSE_DEPLOYMENTS=(
  "secflow-app-entry-analyse:secflow-app-entry-analyse"
  "secflow-app-entry-analyse-scheduler:secflow-app-entry-analyse-scheduler"
  "secflow-app-entry-analyse-worker:secflow-app-entry-analyse-worker"
)
SYSTEM_ANALYSE_DEPLOYMENTS=(
  "secflow-app-system-analyse:secflow-app-system-analyse"
  "secflow-app-system-analyse-worker:secflow-app-system-analyse-worker"
  "secflow-app-system-analyse-runner:secflow-app-system-analyse-runner"
)
FRONTEND_DEPLOYMENT="secflow-platform-frontend"
FRONTEND_CONTAINER="secflow-platform-frontend"
CHIRMERA_SCHEDULE_DEPLOYMENTS=(
  "chirmera-platform-schedule-api:chirmera-platform-schedule"
  "chirmera-platform-schedule-scheduler:chirmera-platform-schedule"
  "chirmera-platform-schedule-worker:chirmera-platform-schedule"
)
EXCLUDED_WORKLOADS=(
  "statefulset/secflow-pi-re-agent"
  "statefulset/secflow-platform-mysql"
  "deployment/secflow-app-dataflow-vuln-scanner-api"
  "deployment/secflow-app-dataflow-vuln-scanner-manager"
  "statefulset/secflow-app-dataflow-vuln-scanner-worker"
)

usage() {
  cat <<'HELP'
Usage:
  ./update_k8s_image_all.sh
  ./update_k8s_image_all.sh [global_tag]
  ./update_k8s_image_all.sh --tag <tag> [--b2s-image <image_or_tag>] [--binary-evolution-image <image_or_tag>] [--binary-security-image <image_or_tag>] [--entry-analyse-image <image_or_tag>] [--system-analyse-image <image_or_tag>] [--frontend-image <image_or_tag>] [--resource-image <image_or_tag>] [--gateway-worker-image <image_or_tag>] [--firmware-unpacker-image <image_or_tag>] [--chirmera-schedule-image <image_or_tag>]

Examples:
  ./update_k8s_image_all.sh
  ./update_k8s_image_all.sh latest
  ./update_k8s_image_all.sh --tag 20260508-abcdef0
  ./update_k8s_image_all.sh --binary-evolution-image 20260512-abcdef0
  ./update_k8s_image_all.sh --entry-analyse-image ghcr.io/runshine/secflow-app-entry-analyse:latest
  ./update_k8s_image_all.sh --binary-security-image 20260513-af453b4
  ./update_k8s_image_all.sh --resource-image 20260403
  ./update_k8s_image_all.sh --gateway-worker-image ghcr.io/runshine/secflow-platform-resource-file-gateway-worker:latest
  ./update_k8s_image_all.sh --firmware-unpacker-image 20260428
  ./update_k8s_image_all.sh --chirmera-schedule-image 20260606

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
  - system-analyse image: override system-analyse api/worker/runner image.
  - frontend image: override secflow platform frontend image.
  - resource image: override secflow-platform-resource image.
  - gateway-worker image: update file_gateway.worker_image in resource ConfigMap template vars.
  - firmware-unpacker image: override secflow-app-firmware-unpacker image.
  - chirmera-schedule image: override chirmera-platform-schedule api/scheduler/worker image.
  - ENTRY_ANALYSE_WORKER_REPLICAS env: desired entry-analyse worker replicas, default 4.
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

is_excluded_workload() {
  local workload_kind="${1:-}"
  local workload_name="${2:-}"
  local item
  for item in "${EXCLUDED_WORKLOADS[@]}"; do
    if [[ "${item}" == "${workload_kind}/${workload_name}" ]]; then
      return 0
    fi
  done
  return 1
}

workload_has_managed_repo() {
  local workload_kind="${1:-}"
  local workload_name="${2:-}"
  local images image repo
  images="$(kubectl -n "${NAMESPACE}" get "${workload_kind}" "${workload_name}" -o jsonpath='{range .spec.template.spec.containers[*]}{.image}{"\n"}{end}' 2>/dev/null || true)"
  while IFS= read -r image; do
    [[ -n "${image}" ]] || continue
    repo="$(image_repo "${image}")"
    if is_managed_repo "${repo}"; then
      return 0
    fi
  done <<< "${images}"
  return 1
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

update_workload_container() {
  local workload_kind="${1:-}"
  local workload_name="${2:-}"
  local container="${3:-}"
  local current_image="${4:-}"
  local requested="${5:-}"
  if is_excluded_workload "${workload_kind}" "${workload_name}"; then
    echo "[INFO] Skipping excluded workload ${workload_kind}/${workload_name}"
    return 0
  fi
  local target_image
  target_image="$(resolve_target_image "${current_image}" "${requested}")"
  if [[ "${target_image}" == "${current_image}" ]]; then
    echo "[INFO] ${workload_name}/${container} already uses ${current_image}"
    return 0
  fi
  echo "[INFO] Updating ${workload_name}/${container}"
  echo "       ${current_image} -> ${target_image}"
  kubectl -n "${NAMESPACE}" set image "${workload_kind}/${workload_name}" "${container}"="${target_image}" >/dev/null
}

workload_exists() {
  local workload_kind="${1:-}"
  local workload_name="${2:-}"
  kubectl -n "${NAMESPACE}" get "${workload_kind}" "${workload_name}" >/dev/null 2>&1
}

maybe_set_explicit_image() {
  local workload_name="${1:-}"
  local container="${2:-}"
  local target_image="${3:-}"
  local workload_kind="${4:-deployment}"
  [[ -n "${workload_name}" && -n "${container}" && -n "${target_image}" ]] || return 0
  workload_exists "${workload_kind}" "${workload_name}" || return 0
  local current_image
  current_image="$(kubectl -n "${NAMESPACE}" get "${workload_kind}" "${workload_name}" -o jsonpath="{.spec.template.spec.containers[?(@.name=='${container}')].image}" 2>/dev/null || true)"
  [[ -n "${current_image}" ]] || return 0
  update_workload_container "${workload_kind}" "${workload_name}" "${container}" "${current_image}" "${target_image}"
}

scale_deployment_if_exists() {
  local deployment="${1:-}"
  local replicas="${2:-}"
  [[ -n "${deployment}" && -n "${replicas}" ]] || return 0
  workload_exists "deployment" "${deployment}" || return 0
  echo "[INFO] Scaling ${deployment} to ${replicas} replicas"
  kubectl -n "${NAMESPACE}" scale deployment "${deployment}" --replicas="${replicas}" >/dev/null
}

B2S_IMAGE_ARG=""
BIN_EVOLUTION_IMAGE_ARG=""
BIN_SECURITY_IMAGE_ARG=""
ENTRY_ANALYSE_IMAGE_ARG=""
SYSTEM_ANALYSE_IMAGE_ARG=""
FRONTEND_IMAGE_ARG=""
RESOURCE_IMAGE_ARG=""
GATEWAY_WORKER_IMAGE_ARG=""
FW_UNPACKER_IMAGE_ARG=""
CHIRMERA_SCHEDULE_IMAGE_ARG=""
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
    --chirmera-schedule-image)
      CHIRMERA_SCHEDULE_IMAGE_ARG="${2:-}"
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
SYSTEM_ANALYSE_IMAGE="$(resolve_image "${SYSTEM_ANALYSE_IMAGE_ARG}" "${SYSTEM_ANALYSE_IMAGE_REPO}")"
FRONTEND_IMAGE="$(resolve_image "${FRONTEND_IMAGE_ARG}" "${FRONTEND_IMAGE_REPO}")"
RESOURCE_IMAGE="$(resolve_image "${RESOURCE_IMAGE_ARG}" "${RESOURCE_IMAGE_REPO}")"
GATEWAY_WORKER_IMAGE="$(resolve_image "${GATEWAY_WORKER_IMAGE_ARG}" "${GATEWAY_WORKER_IMAGE_REPO}")"
FW_UNPACKER_IMAGE="$(resolve_image "${FW_UNPACKER_IMAGE_ARG}" "${FW_UNPACKER_IMAGE_REPO}")"
CHIRMERA_SCHEDULE_IMAGE="$(resolve_image "${CHIRMERA_SCHEDULE_IMAGE_ARG}" "${CHIRMERA_SCHEDULE_IMAGE_REPO}")"

if [[ -f "${SCRIPT_DIR}/images.env" ]]; then
  # shellcheck disable=SC1091
  source "${SCRIPT_DIR}/images.env"
fi

if [[ -n "${CHIRMERA_SCHEDULE_IMAGE}" ]]; then
  export CHIRMERA_PLATFORM_SCHEDULE_IMAGE="${CHIRMERA_SCHEDULE_IMAGE}"
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
scale_deployment_if_exists "secflow-app-entry-analyse-worker" "${ENTRY_ANALYSE_WORKER_REPLICAS}"


for pair in "${SYSTEM_ANALYSE_DEPLOYMENTS[@]}"; do
  maybe_set_explicit_image "${pair%%:*}" "${pair##*:}" "${SYSTEM_ANALYSE_IMAGE}"
done

maybe_set_explicit_image "${BIN_SECURITY_API_DEPLOYMENT}" "secflow-app-binary-security" "${BIN_SECURITY_IMAGE}"
maybe_set_explicit_image "${BIN_SECURITY_WORKER_DEPLOYMENT}" "secflow-app-binary-security-worker" "${BIN_SECURITY_IMAGE}"
maybe_set_explicit_image "${FRONTEND_DEPLOYMENT}" "${FRONTEND_CONTAINER}" "${FRONTEND_IMAGE}"
maybe_set_explicit_image "${B2S_MANAGER_DEPLOYMENT}" "${B2S_MANAGER_CONTAINER}" "${B2S_IMAGE}"
maybe_set_explicit_image "${B2S_WORKER_DEPLOYMENT}" "${B2S_WORKER_CONTAINER}" "${B2S_IMAGE}"
maybe_set_explicit_image "${BIN_EVOLUTION_MANAGER_DEPLOYMENT}" "${BIN_EVOLUTION_MANAGER_CONTAINER}" "${BIN_EVOLUTION_IMAGE}"
maybe_set_explicit_image "${BIN_EVOLUTION_WORKER_DEPLOYMENT}" "${BIN_EVOLUTION_WORKER_CONTAINER}" "${BIN_EVOLUTION_IMAGE}"
maybe_set_explicit_image "secflow-app-firmware-unpacker-api" "secflow-app-firmware-unpacker" "${FW_UNPACKER_IMAGE}"
maybe_set_explicit_image "secflow-app-firmware-unpacker-dispatcher" "secflow-app-firmware-unpacker" "${FW_UNPACKER_IMAGE}"
maybe_set_explicit_image "secflow-app-firmware-unpacker-cleanup" "secflow-app-firmware-unpacker" "${FW_UNPACKER_IMAGE}"
for pair in "${CHIRMERA_SCHEDULE_DEPLOYMENTS[@]}"; do
  maybe_set_explicit_image "${pair%%:*}" "${pair##*:}" "${CHIRMERA_SCHEDULE_IMAGE}"
done

echo "[INFO] Scanning workloads in namespace: ${NAMESPACE}"
while IFS=$'\t' read -r workload_kind workload_name containers; do
  [[ -n "${workload_name}" ]] || continue
  [[ "${workload_name}" == secflow-* ]] || continue
  if is_excluded_workload "${workload_kind}" "${workload_name}"; then
    echo "[INFO] Skip excluded workload during image scan: ${workload_kind}/${workload_name}"
    continue
  fi
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
    case "${workload_name}:${container}" in
      "${B2S_MANAGER_DEPLOYMENT}:${B2S_MANAGER_CONTAINER}"|"${B2S_WORKER_DEPLOYMENT}:${B2S_WORKER_CONTAINER}")
        [[ -n "${B2S_IMAGE}" ]] && requested_tag="${B2S_IMAGE}"
        ;;
      "${BIN_EVOLUTION_MANAGER_DEPLOYMENT}:${BIN_EVOLUTION_MANAGER_CONTAINER}"|"${BIN_EVOLUTION_WORKER_DEPLOYMENT}:${BIN_EVOLUTION_WORKER_CONTAINER}")
        [[ -n "${BIN_EVOLUTION_IMAGE}" ]] && requested_tag="${BIN_EVOLUTION_IMAGE}"
        ;;
      "${BIN_SECURITY_API_DEPLOYMENT}:secflow-app-binary-security"|"${BIN_SECURITY_WORKER_DEPLOYMENT}:secflow-app-binary-security-worker")
        [[ -n "${BIN_SECURITY_IMAGE}" ]] && requested_tag="${BIN_SECURITY_IMAGE}"
        ;;
      "secflow-app-entry-analyse:secflow-app-entry-analyse"|"secflow-app-entry-analyse-scheduler:secflow-app-entry-analyse-scheduler"|"secflow-app-entry-analyse-worker:secflow-app-entry-analyse-worker")
        [[ -n "${ENTRY_ANALYSE_IMAGE}" ]] && requested_tag="${ENTRY_ANALYSE_IMAGE}"
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
      "chirmera-platform-schedule-api:chirmera-platform-schedule"|"chirmera-platform-schedule-scheduler:chirmera-platform-schedule"|"chirmera-platform-schedule-worker:chirmera-platform-schedule")
        [[ -n "${CHIRMERA_SCHEDULE_IMAGE}" ]] && requested_tag="${CHIRMERA_SCHEDULE_IMAGE}"
        ;;
    esac
    update_workload_container "${workload_kind}" "${workload_name}" "${container}" "${current_image}" "${requested_tag}"
  done
done < <(
  {
    kubectl -n "${NAMESPACE}" get deploy \
      -o jsonpath='{range .items[*]}{"deployment"}{"\t"}{.metadata.name}{"\t"}{range .spec.template.spec.containers[*]}{.name}{"="}{.image}{";"}{end}{"\n"}{end}'
    kubectl -n "${NAMESPACE}" get sts \
      -o jsonpath='{range .items[*]}{"statefulset"}{"\t"}{.metadata.name}{"\t"}{range .spec.template.spec.containers[*]}{.name}{"="}{.image}{";"}{end}{"\n"}{end}'
  }
)

echo "[INFO] Forcing rollout restart for secflow workloads"
while IFS=$'\t' read -r workload_kind workload_name; do
  [[ -n "${workload_name}" ]] || continue
  if is_excluded_workload "${workload_kind}" "${workload_name}"; then
    echo "[INFO] Skip excluded workload restart: ${workload_kind}/${workload_name}"
    continue
  fi
  if ! workload_has_managed_repo "${workload_kind}" "${workload_name}"; then
    echo "[INFO] Skip unmanaged workload restart: ${workload_kind}/${workload_name}"
    continue
  fi
  kubectl -n "${NAMESPACE}" rollout restart "${workload_kind}/${workload_name}"
done < <(
  {
    kubectl -n "${NAMESPACE}" get deploy -o jsonpath='{range .items[*]}{"deployment"}{"\t"}{.metadata.name}{"\n"}{end}'
    kubectl -n "${NAMESPACE}" get sts -o jsonpath='{range .items[*]}{"statefulset"}{"\t"}{.metadata.name}{"\n"}{end}'
  } | grep -E $'^.*\t(secflow-|chirmera-platform-schedule-)'
)

echo "[INFO] Waiting for secflow workloads to finish rollout"
while IFS=$'\t' read -r workload_kind workload_name; do
  [[ -n "${workload_name}" ]] || continue
  if is_excluded_workload "${workload_kind}" "${workload_name}"; then
    continue
  fi
  if ! workload_has_managed_repo "${workload_kind}" "${workload_name}"; then
    continue
  fi
  kubectl -n "${NAMESPACE}" rollout status "${workload_kind}/${workload_name}" --timeout=300s
done < <(
  {
    kubectl -n "${NAMESPACE}" get deploy -o jsonpath='{range .items[*]}{"deployment"}{"\t"}{.metadata.name}{"\n"}{end}'
    kubectl -n "${NAMESPACE}" get sts -o jsonpath='{range .items[*]}{"statefulset"}{"\t"}{.metadata.name}{"\n"}{end}'
  } | grep -E $'^.*\t(secflow-|chirmera-platform-schedule-)'
)

echo "[INFO] Done"
