#!/bin/bash

# 设置 TLS 证书和 Kubernetes Secret 的函数
setup_tls_secret() {
    local domain="$1"
    local namespace="$2"
    local secret_name="$3"

    echo "正在设置 ${domain} 的 TLS 证书和 Secret..."

    # 生成 TLS 证书
    ./setup-tls-cert.sh "${domain}"

    cat "certs/${domain}.crt" "certs/ca.crt" > "certs/${domain}_fullchain.crt"

    # 删除已存在的 Secret（如果存在）
    kubectl delete secret "${secret_name}" -n "${namespace}" 2>/dev/null || true

    # 创建新的 TLS Secret
    kubectl create secret tls "${secret_name}" \
        --namespace "${namespace}" \
        --key "certs/${domain}.key" \
        --cert "certs/${domain}_fullchain.crt"

    echo "Secret '${secret_name}' 已在命名空间 '${namespace}' 中创建"
    echo "---"
}

# 主函数
main() {
    echo "开始设置 TLS 证书和 Kubernetes Secrets..."
    echo ""

    # 设置第一个域
    setup_tls_secret "*.sothothv2.com"             "sothothv2-ns" "wildcard-sothothv2.com-tls"

    # 设置第二个域
    setup_tls_secret "*.code-server.sothothv2.com" "vscode" "      wildcard-code-server.sothothv2.com-tls"

    echo -e "\n=== 设置完成！ ==="
}

# 检查是否直接运行脚本（而不是被 source）
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi