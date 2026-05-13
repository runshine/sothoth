#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-secflow-ns}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DFVS_IMAGE="${DFVS_IMAGE:-}"
BINARY_SECURITY_IMAGE="${BINARY_SECURITY_IMAGE:-}"
FRONTEND_IMAGE="${FRONTEND_IMAGE:-}"
SCALE_LEGACY_FIRST="${SCALE_LEGACY_FIRST:-1}"

LEGACY_DEPLOYMENT="secflow-app-dataflow-vuln-scanner"
MANAGER_DEPLOYMENT="secflow-app-dataflow-vuln-scanner-manager"
WORKER_STATEFULSET="secflow-app-dataflow-vuln-scanner-worker"
MANAGER_CONTAINER="secflow-app-dataflow-vuln-scanner-manager"
WORKER_CONTAINER="secflow-app-dataflow-vuln-scanner-worker"

usage() {
  cat <<'HELP'
Usage:
  DFVS_IMAGE=ghcr.io/runshine/secflow-app-dataflow-vuln-scanner:<tag> \
  BINARY_SECURITY_IMAGE=ghcr.io/runshine/secflow-app-binary-security:<tag> \
  FRONTEND_IMAGE=ghcr.io/runshine/secflow-frontend:<tag> \
  ./migrate_dataflow_vuln_scanner_manager_worker.sh

Environment:
  NAMESPACE             Kubernetes namespace, default secflow-ns.
  DFVS_IMAGE            Optional new dataflow-vuln-scanner image for manager + worker.
  BINARY_SECURITY_IMAGE Optional new binary-security image after client contract update.
  FRONTEND_IMAGE        Optional new frontend image after downstream creator update.
  SCALE_LEGACY_FIRST    1 by default. Scale old standalone Deployment to 0 before
                        creating heavy worker Pods to avoid resource pressure. Set 0
                        only if the cluster has enough spare CPU/memory.
HELP
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

kubectl_exists() {
  kubectl -n "${NAMESPACE}" get "$1" "$2" >/dev/null 2>&1
}

rollout_status_if_exists() {
  local kind="$1"
  local name="$2"
  local timeout="${3:-600s}"
  if kubectl_exists "${kind}" "${name}"; then
    kubectl -n "${NAMESPACE}" rollout status "${kind}/${name}" --timeout="${timeout}"
  fi
}

echo "[INFO] Namespace: ${NAMESPACE}"
echo "[INFO] Applying dataflow-vuln-scanner ConfigMap"
kubectl apply -f "${SCRIPT_DIR}/00-secflow-107-00-app-dataflow-vuln-scanner-configmap.yaml"

if [[ "${SCALE_LEGACY_FIRST}" == "1" ]] && kubectl_exists deployment "${LEGACY_DEPLOYMENT}"; then
  echo "[INFO] Scaling legacy standalone Deployment ${LEGACY_DEPLOYMENT} to 0"
  kubectl -n "${NAMESPACE}" scale deployment "${LEGACY_DEPLOYMENT}" --replicas=0
  rollout_status_if_exists deployment "${LEGACY_DEPLOYMENT}" 300s
fi

echo "[INFO] Applying manager Deployment + worker StatefulSet"
kubectl apply -f "${SCRIPT_DIR}/00-secflow-107-01-app-dataflow-vuln-scanner-deployment.yaml"

if [[ -n "${DFVS_IMAGE}" ]]; then
  echo "[INFO] Setting DFVS image to ${DFVS_IMAGE}"
  kubectl -n "${NAMESPACE}" set image deployment/${MANAGER_DEPLOYMENT} "${MANAGER_CONTAINER}=${DFVS_IMAGE}"
  kubectl -n "${NAMESPACE}" set image statefulset/${WORKER_STATEFULSET} "${WORKER_CONTAINER}=${DFVS_IMAGE}"
  # Force re-pull when the tag is reused (for example :latest).
  kubectl -n "${NAMESPACE}" rollout restart deployment/${MANAGER_DEPLOYMENT}
  kubectl -n "${NAMESPACE}" rollout restart statefulset/${WORKER_STATEFULSET}
fi

rollout_status_if_exists deployment "${MANAGER_DEPLOYMENT}" 600s
rollout_status_if_exists statefulset "${WORKER_STATEFULSET}" 1200s

echo "[INFO] Switching Service to manager Pods and ensuring worker headless Service"
kubectl apply -f "${SCRIPT_DIR}/00-secflow-107-02-app-dataflow-vuln-scanner-service.yaml"

if kubectl_exists deployment "${LEGACY_DEPLOYMENT}"; then
  echo "[INFO] Deleting legacy standalone Deployment ${LEGACY_DEPLOYMENT}"
  kubectl -n "${NAMESPACE}" delete deployment "${LEGACY_DEPLOYMENT}"
fi

if [[ -n "${BINARY_SECURITY_IMAGE}" ]] && kubectl_exists deployment "secflow-app-binary-security"; then
  echo "[INFO] Updating binary-security image to ${BINARY_SECURITY_IMAGE}"
  kubectl -n "${NAMESPACE}" set image deployment/secflow-app-binary-security secflow-app-binary-security="${BINARY_SECURITY_IMAGE}"
  kubectl -n "${NAMESPACE}" rollout restart deployment/secflow-app-binary-security
  rollout_status_if_exists deployment secflow-app-binary-security 600s
fi

if [[ -n "${FRONTEND_IMAGE}" ]] && kubectl_exists deployment "secflow-platform-frontend"; then
  echo "[INFO] Updating frontend image to ${FRONTEND_IMAGE}"
  kubectl -n "${NAMESPACE}" set image deployment/secflow-platform-frontend secflow-platform-frontend="${FRONTEND_IMAGE}"
  kubectl -n "${NAMESPACE}" rollout restart deployment/secflow-platform-frontend
  rollout_status_if_exists deployment secflow-platform-frontend 600s
fi

echo "[INFO] Current DFVS workloads"
kubectl -n "${NAMESPACE}" get deploy,statefulset,svc,pod -o wide | grep -E 'dataflow-vuln-scanner|NAME' || true

echo "[INFO] Done. Verify:"
echo "  kubectl -n ${NAMESPACE} get endpoints secflow-app-dataflow-vuln-scanner secflow-app-dataflow-vuln-scanner-worker-headless -o wide"
echo "  curl -k https://secflow.ai.icsl.huawei.com/api/dataflow-vuln-scanner/health"
