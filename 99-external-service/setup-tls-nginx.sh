#!/bin/bash

# 设置变量



./setup-tls-cert.sh '*.sothothv2.com'
kubectl delete secret wildcard-sothothv2.com-tls -n sothothv2-ns 2>/dev/null || true
kubectl create secret tls wildcard-sothothv2.com-tls --namespace sothothv2-ns --key 'certs/*.sothothv2.com.key' --cert 'certs/*.sothothv2.com.crt'
echo "Secret 'wildcard-sothothv2.com-tls' 已在命名空间 'sothothv2-ns' 中创建"

./setup-tls-cert.sh '*.code-server.sothothv2.com'
kubectl delete secret wildcard-code-server.sothothv2.com-tls -n vscode 2>/dev/null || true
kubectl create secret tls wildcard-code-server.sothothv2.com-tls --namespace vscode --key 'certs/*.code-server.sothothv2.com.key' --cert 'certs/*.code-server.sothothv2.com.crt'
echo "Secret 'wildcard-code-server.sothothv2.com-tls' 已在命名空间 'vscode' 中创建"


echo -e "\n=== 设置完成！ ==="
