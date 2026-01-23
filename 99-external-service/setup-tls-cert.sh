#!/bin/bash

# 证书存储目录
CERTS_DIR="./certs"
CA_KEY="$CERTS_DIR/ca.key"
CA_CRT="$CERTS_DIR/ca.crt"
CA_SRL="$CERTS_DIR/ca.srl"

# 检查参数
if [ $# -ne 1 ]; then
    echo "用法: $0 <泛域名>"
    echo "示例: $0 '*.example.com'"
    exit 1
fi

DOMAIN="$1"
# 从泛域名中提取基础域名（去掉*号）
BASE_DOMAIN=$(echo "$DOMAIN" | sed 's/^\*\.//')
KEY_FILE="$CERTS_DIR/$DOMAIN.key"
CRT_FILE="$CERTS_DIR/$DOMAIN.crt"
CSR_FILE="$CERTS_DIR/$DOMAIN.csr"
EXT_FILE="$CERTS_DIR/$DOMAIN.ext"

# 创建certs目录（如果不存在）
mkdir -p "$CERTS_DIR"

# 函数：创建CA证书
create_ca_certificate() {
    echo "创建CA证书..."

    # 生成CA私钥
    openssl genrsa -out "$CA_KEY" 2048

    # 生成CA自签名证书
    openssl req -new -x509 -days 3650 -key "$CA_KEY" -out "$CA_CRT" \
        -subj "/C=CN/ST=State/L=City/O=Organization/OU=Unit/CN=sothothv2.com"

    echo "CA证书已创建:"
    echo "  - 私钥: $CA_KEY"
    echo "  - 证书: $CA_CRT"
    echo ""
    echo "请将 $CA_CRT 导入系统根证书存储"
    echo ""
}

# 函数：创建泛域名证书
create_domain_certificate() {
    local domain="$1"
    local base_domain="$2"

    echo "为域名: $domain 创建证书..."

    # 生成私钥
    openssl genrsa -out "$KEY_FILE" 2048

    # 生成证书签名请求(CSR) - CN使用带*号的泛域名
    openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" \
        -subj "/C=CN/ST=State/L=City/O=Organization/OU=Unit/CN=$domain"

    # 创建扩展配置文件
    cat > "$EXT_FILE" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $domain
DNS.2 = $base_domain
EOF

    # 使用CA证书签名
    openssl x509 -req -days 3650 -in "$CSR_FILE" -CA "$CA_CRT" -CAkey "$CA_KEY" \
        -CAcreateserial -out "$CRT_FILE" -extfile "$EXT_FILE"

    # 清理临时文件
    rm -f "$CSR_FILE" "$EXT_FILE"

    echo "证书已创建:"
    echo "  - 私钥: $KEY_FILE"
    echo "  - 证书: $CRT_FILE"
    echo ""
}

# 主流程
echo "===== 证书管理脚本 ====="
echo "目标域名: $DOMAIN"
echo "证书目录: $CERTS_DIR"
echo ""

# 检查CA证书是否存在
if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CRT" ]; then
    echo "CA证书不存在，开始创建..."
    create_ca_certificate
else
    echo "CA证书已存在，跳过创建"
    echo "  - 私钥: $CA_KEY"
    echo "  - 证书: $CA_CRT"
    echo ""
fi

# 检查域名证书是否存在
if [ ! -f "$KEY_FILE" ] || [ ! -f "$CRT_FILE" ]; then
    echo "域名证书不存在，开始创建..."
    create_domain_certificate "$DOMAIN" "$BASE_DOMAIN"

    # 显示证书信息
    echo "证书详情:"
    openssl x509 -in "$CRT_FILE" -noout -text | grep -A1 "Subject:"
    openssl x509 -in "$CRT_FILE" -noout -text | grep -A2 "Subject Alternative Name"
    echo ""
    echo "证书有效期:"
    openssl x509 -in "$CRT_FILE" -noout -dates
else
    echo "域名证书已存在，跳过创建"
    echo "  - 私钥: $KEY_FILE"
    echo "  - 证书: $CRT_FILE"
    echo ""

    # 显示现有证书信息
    echo "现有证书详情:"
    openssl x509 -in "$CRT_FILE" -noout -text | grep -A1 "Subject\|Not"
    echo ""
fi

echo "===== 完成 ====="