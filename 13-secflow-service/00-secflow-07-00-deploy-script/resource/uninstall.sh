#!/bin/bash

set -eu

ROOT_DIR="${1:-/sothothv2}"
CONFIG_FILE="${ROOT_DIR}/config/sothothv2_agent.ini"

if [ ! -f "${CONFIG_FILE}" ]; then
  echo "config not found: ${CONFIG_FILE}" >&2
  exit 1
fi

API_LISTEN="$(awk -F= '/^api_listen=/{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' "${CONFIG_FILE}")"
API_TOKEN="$(awk -F= '/^api_auth_token=/{sub(/^[^=]*=/, ""); gsub(/^[ \t]+|[ \t]+$/, "", $0); print $0}' "${CONFIG_FILE}")"

if [ -z "${API_LISTEN}" ]; then
  API_LISTEN=":11188"
fi

HOST_PART="${API_LISTEN%:*}"
PORT_PART="${API_LISTEN##*:}"
if [ -z "${PORT_PART}" ]; then
  PORT_PART="11188"
fi
if [ -z "${HOST_PART}" ] || [ "${HOST_PART}" = "${API_LISTEN}" ]; then
  HOST_PART="127.0.0.1"
fi

URL="http://${HOST_PART}:${PORT_PART}/api/v1/agent/uninstall"

echo "trigger uninstall via ${URL}"
curl -fsS -X POST \
  -H "X-Auth-Token: ${API_TOKEN}" \
  "${URL}"
