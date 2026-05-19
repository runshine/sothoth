#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-secflow-app-kernel-scan:local}"

"${ROOT_DIR}/scripts/prepare-android-tools.sh"

docker build \
    --build-arg "ANDROID_PLATFORM_TOOLS_URL=${ANDROID_PLATFORM_TOOLS_URL:-https://dl.google.com/android/repository/platform-tools-latest-linux.zip}" \
    --build-arg "ANDROID_NDK_URL=${ANDROID_NDK_URL:-https://dl.google.com/android/repository/android-ndk-r29-linux.zip}" \
    --build-arg "ANDROID_NDK_SHA1=${ANDROID_NDK_SHA1:-}" \
    -t "$IMAGE" \
    "$@" \
    "$ROOT_DIR"
