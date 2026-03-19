#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../00-pre-init/setup-k8s-tls-secrets.sh"

setup_tls_secret "*.sothothv2.com"             "sothothv2-ns" "wildcard-sothothv2.com-tls"
setup_tls_secret "*.sothothv2.com"             "sothoth"      "wildcard-sothothv2.com-tls"
setup_tls_secret "*.sothothv2.com"             "secflow-ns"   "wildcard-sothothv2.com-tls"
setup_tls_secret "*.code-server.sothothv2.com" "vscode" "wildcard-code-server.sothothv2.com-tls"
