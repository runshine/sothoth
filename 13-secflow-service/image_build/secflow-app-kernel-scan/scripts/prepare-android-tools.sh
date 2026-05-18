#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_DIR="${ANDROID_TOOLS_CACHE_DIR:-${ROOT_DIR}/tools}"

PLATFORM_TOOLS_URL="${ANDROID_PLATFORM_TOOLS_URL:-https://dl.google.com/android/repository/platform-tools-latest-linux.zip}"
NDK_URL="${ANDROID_NDK_URL:-https://dl.google.com/android/repository/android-ndk-r29-linux.zip}"
NDK_SHA1="${ANDROID_NDK_SHA1:-dc5bd963c8fd5ba91762a8a282b39466fb7f6568}"

PLATFORM_TOOLS_ZIP="${TOOLS_DIR}/android-platform-tools.zip"
NDK_ZIP="${TOOLS_DIR}/android-ndk-r29.zip"

download_if_missing() {
    local url="$1"
    local dest="$2"
    local name="$3"

    mkdir -p "$(dirname "$dest")"

    if [ -s "$dest" ]; then
        echo "[tools] using cached ${name}: ${dest}"
        return
    fi

    echo "[tools] downloading ${name}: ${url}"
    local tmp="${dest}.tmp"
    rm -f "$tmp"
    curl -fL --retry 3 --retry-delay 5 -o "$tmp" "$url"
    mv "$tmp" "$dest"
}

verify_sha1() {
    local expected="$1"
    local file="$2"

    if command -v sha1sum >/dev/null 2>&1; then
        echo "${expected}  ${file}" | sha1sum -c -
        return
    fi

    if command -v shasum >/dev/null 2>&1; then
        local actual
        actual="$(shasum -a 1 "$file" | awk '{print $1}')"
        if [ "$actual" != "$expected" ]; then
            echo "${file}: FAILED" >&2
            echo "expected ${expected}, got ${actual}" >&2
            return 1
        fi
        echo "${file}: OK"
        return
    fi

    echo "[tools] warning: neither sha1sum nor shasum is available; skipping SHA1 check" >&2
}

download_if_missing "$PLATFORM_TOOLS_URL" "$PLATFORM_TOOLS_ZIP" "Android platform-tools"
download_if_missing "$NDK_URL" "$NDK_ZIP" "Android NDK r29"

if [ -n "$NDK_SHA1" ]; then
    verify_sha1 "$NDK_SHA1" "$NDK_ZIP"
fi

echo "[tools] cache ready: ${TOOLS_DIR}"
