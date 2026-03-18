#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="${NAMESPACE:-secflow-ns}"
TIMEOUT="${TIMEOUT:-600s}"
CURL_POD="${CURL_POD:-secflow-e2e-curl}"
SKIP_APPLY="${SKIP_APPLY:-0}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

pass_count=0
fail_count=0
rollout_failures=()

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err() { echo -e "${RED}[ERR ]${NC} $*"; }

require_bin() {
  command -v "$1" >/dev/null 2>&1 || { log_err "缺少依赖: $1"; exit 1; }
}

apply_all_manifests() {
  log_info "应用全部K8S清单..."
  # 按文件名排序，确保顺序稳定（00-xx 前缀已编码依赖顺序）
  mapfile -t files < <(find "$ROOT_DIR" -maxdepth 1 -type f -name '*.yaml' | sort)
  for f in "${files[@]}"; do
    log_info "kubectl apply -f $(basename "$f")"
    kubectl apply -f "$f"
  done
}

wait_deployments_ready() {
  log_info "等待Deployment就绪..."
  local deployments=(
    secflow-platform-frontend
    secflow-platform-menu
    secflow-platform-auth
    secflow-platform-project
    secflow-platform-resource
    secflow-platform-static-binary
    secflow-platform-deploy-script
    secflow-platform-agent
    secflow-platform-k8s
    secflow-platform-workflow
    secflow-app-code-server
    secflow-app-secmate-ng
  )

  for d in "${deployments[@]}"; do
    log_info "rollout status deploy/${d} (timeout=${TIMEOUT})"
    if ! kubectl -n "$NAMESPACE" rollout status "deploy/${d}" --timeout="$TIMEOUT"; then
      log_err "Deployment未就绪: ${d}"
      rollout_failures+=("$d")
      ((fail_count+=1))
    fi
  done
}

print_rollout_diagnostics() {
  if [[ "${#rollout_failures[@]}" -eq 0 ]]; then
    return 0
  fi
  log_warn "输出未就绪Deployment的简要诊断..."
  for d in "${rollout_failures[@]}"; do
    echo "----- ${d} -----"
    kubectl -n "$NAMESPACE" get deploy "$d" -o wide || true
    kubectl -n "$NAMESPACE" get pod -l "name=${d}" -o wide || true
    kubectl -n "$NAMESPACE" describe deploy "$d" | sed -n '1,120p' || true
  done
}

start_curl_pod() {
  log_info "创建测试Pod: ${CURL_POD}"
  kubectl -n "$NAMESPACE" delete pod "$CURL_POD" --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NAMESPACE" run "$CURL_POD" \
    --image=curlimages/curl:8.10.1 \
    --restart=Never \
    --command -- sh -c 'sleep 3600' >/dev/null
  kubectl -n "$NAMESPACE" wait --for=condition=Ready "pod/${CURL_POD}" --timeout=120s >/dev/null
}

cleanup_curl_pod() {
  kubectl -n "$NAMESPACE" delete pod "$CURL_POD" --ignore-not-found >/dev/null 2>&1 || true
}

check_http() {
  local svc="$1"
  local path="$2"
  local expect_substr="${3:-}"
  local url="http://${svc}.${NAMESPACE}.svc.cluster.local${path}"

  local output
  if ! output="$(kubectl -n "$NAMESPACE" exec "$CURL_POD" -- sh -lc \
    "body=\$(curl -sS -m 12 -o /tmp/resp_body -w '%{http_code}' '${url}' || echo 000); echo \$body; head -c 4096 /tmp/resp_body 2>/dev/null || true")"; then
    log_err "请求失败: ${url}"
    ((fail_count+=1))
    return 1
  fi

  local code
  code="$(echo "$output" | head -n1 | tr -d '\r')"
  local body
  body="$(echo "$output" | tail -n +2)"

  if [[ "$code" != "200" ]]; then
    log_err "HTTP ${code}: ${url}"
    ((fail_count+=1))
    return 1
  fi

  if [[ -n "$expect_substr" ]] && [[ "$body" != *"$expect_substr"* ]]; then
    log_err "内容校验失败: ${url} (未找到: ${expect_substr})"
    ((fail_count+=1))
    return 1
  fi

  log_info "PASS ${url}"
  ((pass_count+=1))
  return 0
}

run_smoke_tests() {
  log_info "执行前后端冒烟测试..."
  start_curl_pod
  trap cleanup_curl_pod EXIT

  # 前端
  check_http "secflow-platform-frontend" "/" "<html" || true

  # 后端微服务健康检查
  check_http "secflow-platform-menu" "/api/menu/health" "\"status\"" || true
  check_http "secflow-platform-auth" "/api/auth/health" "\"status\"" || true
  check_http "secflow-platform-project" "/api/project/health" "\"status\"" || true
  check_http "secflow-platform-resource" "/api/resource/health" "\"status\"" || true
  check_http "secflow-platform-agent" "/api/agent/health" "\"status\"" || true
  check_http "secflow-platform-k8s" "/api/k8s/health" "\"status\"" || true
  check_http "secflow-platform-workflow" "/api/workflow/health" "\"status\"" || true
  check_http "secflow-platform-static-binary" "/api/packages/health" "\"status\"" || true
  check_http "secflow-platform-deploy-script" "/api/deploy-script/health" "\"status\"" || true
  check_http "secflow-app-code-server" "/api/app/code-server/health" "\"status\"" || true
  check_http "secflow-app-secmate-ng" "/api/app/secmate-ng/health" "\"status\"" || true

  cleanup_curl_pod
  trap - EXIT
}

show_summary() {
  echo
  log_info "测试汇总: PASS=${pass_count}, FAIL=${fail_count}"
  if [[ "${#rollout_failures[@]}" -gt 0 ]]; then
    log_warn "Rollout失败列表: ${rollout_failures[*]}"
  fi
  if [[ "$fail_count" -gt 0 ]]; then
    log_err "存在失败项，请执行: kubectl -n ${NAMESPACE} get pods"
    exit 2
  fi
}

main() {
  require_bin kubectl
  kubectl cluster-info >/dev/null

  if [[ "$SKIP_APPLY" != "1" ]]; then
    apply_all_manifests
  else
    log_warn "SKIP_APPLY=1，跳过kubectl apply"
  fi

  wait_deployments_ready
  print_rollout_diagnostics
  run_smoke_tests
  show_summary
}

main "$@"
