#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-secflow-ns}"
DEPLOYMENT="${DEPLOYMENT:-secflow-app-firmware-unpacker}"
CONFIGMAP="${CONFIGMAP:-secflow-app-firmware-unpacker-config}"
CONFIGMAP_MANIFEST="${CONFIGMAP_MANIFEST:-k8s-configmap.yaml}"
DEPLOYMENT_MANIFEST="${DEPLOYMENT_MANIFEST:-k8s-deployment.yaml}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

run_diff() {
  local manifest="$1"
  local label="$2"
  local tmp
  tmp="$(mktemp)"
  set +e
  kubectl diff -n "${NAMESPACE}" -f "${manifest}" >"${tmp}" 2>&1
  local rc=$?
  set -e
  case "${rc}" in
    0)
      echo "${label}: no drift"
      ;;
    1)
      echo "${label}: drift detected"
      cat "${tmp}"
      ;;
    *)
      echo "${label}: diff failed" >&2
      cat "${tmp}" >&2
      rm -f "${tmp}"
      exit "${rc}"
      ;;
  esac
  rm -f "${tmp}"
}

require_cmd kubectl

echo "context=$(kubectl config current-context)"
echo "namespace=${NAMESPACE}"
echo

kubectl -n "${NAMESPACE}" get deployment "${DEPLOYMENT}" >/dev/null
kubectl -n "${NAMESPACE}" get configmap "${CONFIGMAP}" >/dev/null

echo "live deployment:"
kubectl -n "${NAMESPACE}" get deployment "${DEPLOYMENT}" \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}'
echo

echo "live configmap agentflow section:"
if kubectl -n "${NAMESPACE}" get configmap "${CONFIGMAP}" -o yaml | grep -A8 '^    agentflow:'; then
  true
else
  echo "agentflow section not present"
fi
echo

echo "live pod runtime check:"
set +e
POD="$(
  kubectl -n "${NAMESPACE}" get pods --no-headers 2>/dev/null \
    | awk -v deployment="${DEPLOYMENT}" '$1 ~ deployment {print $1; exit}'
)"
set -e
if [ -z "${POD}" ]; then
  echo "no live pod found for ${DEPLOYMENT}"
else
  echo "pod=${POD}"
  set +e
  kubectl -n "${NAMESPACE}" exec "${POD}" -- sh -lc 'python3 -c "import agentflow; print(agentflow.__file__)" && pi --version'
  rc=$?
  set -e
  if [ "${rc}" -ne 0 ]; then
    echo "live pod runtime check failed; a new image rollout is required"
  fi
fi
echo

echo "client dry-run:"
kubectl apply --dry-run=client -f "${CONFIGMAP_MANIFEST}"
kubectl apply --dry-run=client -f "${DEPLOYMENT_MANIFEST}"
echo

run_diff "${CONFIGMAP_MANIFEST}" "configmap"
echo
run_diff "${DEPLOYMENT_MANIFEST}" "deployment"
