#!/bin/bash

# 设置变量
DOMAIN="sothothv2.com"
WILDCARD_DOMAIN="*.${DOMAIN}"
SECRET_NAME="wildcard-${DOMAIN}-tls"
NAMESPACE="ingress-nginx"
TRAEFIK_NAMESPACE="traefik"
TRAEFIK_SERVICE="traefik"
CERT_DIR="./certs"
DAYS=365

# 创建证书目录
mkdir -p ${CERT_DIR}

echo "=== 1. 生成自签名证书 ==="

# 生成私钥
openssl genrsa -out ${CERT_DIR}/${DOMAIN}.key 2048

# 生成 CSR (证书签名请求)
cat > ${CERT_DIR}/${DOMAIN}.csr.cnf <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
C = CN
ST = Guangdong
L = Shenzhen
O = SothothV2
OU = DevOps
CN = ${WILDCARD_DOMAIN}

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN}
DNS.2 = *.${DOMAIN}
DNS.3 = ${DOMAIN}.localhost
EOF

openssl req -new -key ${CERT_DIR}/${DOMAIN}.key \
  -out ${CERT_DIR}/${DOMAIN}.csr \
  -config ${CERT_DIR}/${DOMAIN}.csr.cnf

# 生成自签名证书
cat > ${CERT_DIR}/${DOMAIN}.ext.cnf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN}
DNS.2 = *.${DOMAIN}
DNS.3 = ${DOMAIN}.localhost
EOF

# 生成 CA 证书（自签名）
openssl req -x509 -new -nodes -key ${CERT_DIR}/${DOMAIN}.key \
  -sha256 -days ${DAYS} \
  -out ${CERT_DIR}/${DOMAIN}.crt \
  -subj "/C=CN/ST=Guangdong/L=Shenzhen/O=SothothV2/OU=DevOps/CN=${WILDCARD_DOMAIN}"

# 使用 CA 证书签署 CSR
openssl x509 -req -in ${CERT_DIR}/${DOMAIN}.csr \
  -CA ${CERT_DIR}/${DOMAIN}.crt \
  -CAkey ${CERT_DIR}/${DOMAIN}.key \
  -CAcreateserial \
  -out ${CERT_DIR}/${DOMAIN}.cert \
  -days ${DAYS} \
  -sha256 \
  -extfile ${CERT_DIR}/${DOMAIN}.ext.cnf

# 创建包含证书链的完整证书（可选）
cat ${CERT_DIR}/${DOMAIN}.cert ${CERT_DIR}/${DOMAIN}.crt > ${CERT_DIR}/${DOMAIN}-fullchain.crt

echo "证书已生成到 ${CERT_DIR}/ 目录"
echo "  - 私钥: ${DOMAIN}.key"
echo "  - 证书: ${DOMAIN}.cert"
echo "  - 完整链: ${DOMAIN}-fullchain.crt"
echo "  - CA证书: ${DOMAIN}.crt"

echo -e "\n=== 2. 验证证书 ==="
openssl x509 -in ${CERT_DIR}/${DOMAIN}.cert -text -noout | grep -A1 "Subject Alternative Name"

echo -e "\n=== 3. 创建 Kubernetes TLS Secret ==="
# 删除现有 secret（如果存在）
kubectl delete secret ${SECRET_NAME} -n ${NAMESPACE} 2>/dev/null || true

# 创建新的 TLS secret
kubectl create secret tls ${SECRET_NAME} \
  --namespace ${NAMESPACE} \
  --key ${CERT_DIR}/${DOMAIN}.key \
  --cert ${CERT_DIR}/${DOMAIN}-fullchain.crt

echo "Secret '${SECRET_NAME}' 已在命名空间 '${NAMESPACE}' 中创建"

echo -e "\n=== 4. 验证 Secret ==="
kubectl get secret ${SECRET_NAME} -n ${NAMESPACE} -o yaml | grep -E "name:|type:"

echo -e "\n=== 5. 创建 Ingress 配置将解密流量转发到 Traefik ==="

cat > vscode-web-manager-07-nginx-traefik-ingress.yaml <<EOF
# 在 ingress-nginx 命名空间中创建一个 ExternalName Service
# 指向 traefik 命名空间中的 traefik Service
apiVersion: v1
kind: Service
metadata:
  name: traefik
  namespace: ingress-nginx  # 重要：创建在 ingress-nginx 命名空间
spec:
  type: ExternalName
  externalName: traefik.kube-system.svc.cluster.local  # 指向 traefik 命名空间的 traefik Service
  ports:
  - port: 80
    targetPort: 80
    protocol: TCP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: nginx-to-traefik
  namespace: ${NAMESPACE}
  annotations:
    # TLS 配置
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
    nginx.ingress.kubernetes.io/proxy-ssl-verify: "off"
    nginx.ingress.kubernetes.io/proxy-set-headers: "ingress-nginx/custom-headers"
    nginx.ingress.kubernetes.io/proxy-buffering: "off"
    nginx.ingress.kubernetes.io/proxy-buffer-size: "16k"
    nginx.ingress.kubernetes.io/proxy-buffers: "4 16k"
    nginx.ingress.kubernetes.io/proxy-connect-timeout: "30"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "1800"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "1800"
    nginx.ingress.kubernetes.io/proxy-body-size: "1024m"

    # 启用 SSL 透传（如果需要 Traefik 也处理 TLS）
    # nginx.ingress.kubernetes.io/ssl-passthrough: "false"

spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - "*.${DOMAIN}"
    - "${DOMAIN}"
    secretName: ${SECRET_NAME}
  rules:
  - host: "*.${DOMAIN}"
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: ${TRAEFIK_SERVICE}
            port:
              number: 80
  - host: "${DOMAIN}"
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: ${TRAEFIK_SERVICE}
            port:
              number: 80
EOF

echo -e "\n=== 6. 创建自定义头部 ConfigMap ==="

cat > vscode-web-manager-06-nginx-traefik-ingress-configmap.yaml <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-traefik-ingress-configmap
  namespace: ${NAMESPACE}
data:
  X-Forwarded-Host: \$host
  X-Forwarded-Proto: \$scheme
  X-Real-IP: \$remote_addr
  X-Forwarded-For: \$proxy_add_x_forwarded_for
  X-Forwarded-Port: \$server_port
  X-Original-URI: \$request_uri
  Host: \$host
EOF

echo -e "\n=== 设置完成！ ==="
