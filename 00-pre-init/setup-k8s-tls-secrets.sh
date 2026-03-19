#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRE_INIT_DIR="${SCRIPT_DIR}"
CERTS_DIR="${PRE_INIT_DIR}/certs"

# 仅允许被 source，不允许直接执行
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "错误: ${BASH_SOURCE[0]} 仅允许通过 source 包含，不允许直接执行"
    echo "示例: source ${BASH_SOURCE[0]}"
    exit 1
fi

# 设置 TLS 证书和 Kubernetes Secret 的函数
setup_tls_secret() {
    local domain="$1"
    local namespace="$2"
    local secret_name="$3"

    echo "正在设置 ${domain} 的 TLS 证书和 Secret..."

    # 生成 TLS 证书
    "${PRE_INIT_DIR}/setup-tls-cert.sh" "${domain}"

    cat "${CERTS_DIR}/${domain}.crt" "${CERTS_DIR}/ca.crt" > "${CERTS_DIR}/${domain}_fullchain.crt"

    # 删除已存在的 Secret（如果存在）
    kubectl delete secret "${secret_name}" -n "${namespace}" 2>/dev/null || true

    # 创建新的 TLS Secret
    kubectl create secret tls "${secret_name}" \
        --namespace "${namespace}" \
        --key "${CERTS_DIR}/${domain}.key" \
        --cert "${CERTS_DIR}/${domain}_fullchain.crt"

    echo "Secret '${secret_name}' 已在命名空间 '${namespace}' 中创建"
    echo "---"
}

# 主函数
main() {
    echo "开始设置 TLS 证书和 Kubernetes Secrets..."
    echo ""

    # 设置第一个域
    setup_tls_secret "*.sothothv2.com"             "sothothv2-ns" "wildcard-sothothv2.com-tls"

    setup_tls_secret "*.sothothv2.com"             "sothoth" "wildcard-sothothv2.com-tls"

    setup_tls_secret "*.sothothv2.com"             "secflow-ns" "wildcard-sothothv2.com-tls"

    # 设置第二个域
    setup_tls_secret "*.code-server.sothothv2.com" "vscode" "wildcard-code-server.sothothv2.com-tls"

    echo -e "\n=== 设置完成！ ==="
}

# 注意：此脚本仅用于被source后调用 main/setup_tls_secret
