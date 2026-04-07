#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../00-pre-init/setup-k8s-tls-secrets.sh"

setup_tls_secret "*.ai.icsl.huawei.com"             "sothothv2-ns" "wildcard-secflow-tls"
setup_tls_secret "*.ai.icsl.huawei.com"             "sothoth"      "wildcard-secflow-tls"
setup_tls_secret "*.ai.icsl.huawei.com"             "secflow-ns"   "wildcard-secflow-tls"
setup_tls_secret "*.code-server.ai.icsl.huawei.com" "vscode"       "wildcard-secflow-tls"
setup_tls_secret "*.gaiasec.ai.icsl.huawei.com"     "sothoth"      "wildcard-secflow-tls"