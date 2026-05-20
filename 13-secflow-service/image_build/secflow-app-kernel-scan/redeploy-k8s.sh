#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_DIR="$(cd "${ROOT_DIR}/../.." && pwd)"

export KUBECONFIG="${KUBECONFIG:-${ROOT_DIR}/config}"
NAMESPACE="${NAMESPACE:-secflow-ns}"
DEPLOYMENT="${DEPLOYMENT:-secflow-app-kernel-scan}"
LABEL_SELECTOR="${LABEL_SELECTOR:-name=secflow-app-kernel-scan}"
ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT:-180s}"

echo ">>> using KUBECONFIG=${KUBECONFIG}"
echo ">>> namespace=${NAMESPACE} deployment=${DEPLOYMENT}"

echo ">>> applying manifests (skip secret; rerun with APPLY_SECRET=1 to include)"
kubectl -n "${NAMESPACE}" apply -f "${MANIFEST_DIR}/00-secflow-111-00-app-kernel-scan-configmap.yaml"
kubectl -n "${NAMESPACE}" apply -f "${MANIFEST_DIR}/00-secflow-111-01-app-kernel-scan-pvc.yaml"
kubectl -n "${NAMESPACE}" apply -f "${MANIFEST_DIR}/00-secflow-111-02-app-kernel-scan-deployment.yaml"
kubectl -n "${NAMESPACE}" apply -f "${MANIFEST_DIR}/00-secflow-111-03-app-kernel-scan-service.yaml"

if [[ "${APPLY_SECRET:-0}" == "1" ]]; then
    echo ">>> APPLY_SECRET=1, applying secret (will overwrite ANTHROPIC_API_KEY)"
    kubectl -n "${NAMESPACE}" apply -f "${MANIFEST_DIR}/00-secflow-111-00a-app-kernel-scan-secret.yaml"
fi

echo ">>> rollout restart to force fresh image pull (imagePullPolicy=Always)"
kubectl -n "${NAMESPACE}" rollout restart "deployment/${DEPLOYMENT}"
kubectl -n "${NAMESPACE}" rollout status "deployment/${DEPLOYMENT}" --timeout="${ROLLOUT_TIMEOUT}"

echo ">>> current pods:"
kubectl -n "${NAMESPACE}" get pod -l "${LABEL_SELECTOR}" -o wide

echo ">>> image actually pulled:"
kubectl -n "${NAMESPACE}" get pod -l "${LABEL_SELECTOR}" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.containerStatuses[?(@.name=="'"${DEPLOYMENT}"'")].image}{"\t"}{.status.containerStatuses[?(@.name=="'"${DEPLOYMENT}"'")].imageID}{"\n"}{end}'
