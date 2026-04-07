#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../00-pre-init/setup-k8s-tls-secrets.sh"

setup_tls_secret "*.harbor.ai.icsl.huawei.com"       "harbor-ns"    "wildcard-secflow-tls"
