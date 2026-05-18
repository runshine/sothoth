#!/bin/bash
set -e

CLAUDE_JSON="$HOME/.claude.json"
SETTINGS_JSON="$HOME/.claude/settings.json"

mkdir -p "$HOME/.claude"

# Copy packaged Claude Code config templates to the user's home on first start.
if [ ! -f "$CLAUDE_JSON" ] && [ -f /app/claude.json.template ]; then
    cp /app/claude.json.template "$CLAUDE_JSON"
fi
if [ ! -f "$SETTINGS_JSON" ] && [ -f /app/settings.json.template ]; then
    cp /app/settings.json.template "$SETTINGS_JSON"
fi

# Patch runtime-bound fields in ~/.claude.json so Claude CLI skips the
# interactive setup even when the API key / trusted dirs differ from the
# machine that generated the template.
if [ -f "$CLAUDE_JSON" ] && command -v jq >/dev/null 2>&1; then
    tmp=$(mktemp)

    # 1) Add current API key hash (first 20 chars of sha256) to approved list.
    if [ -n "$ANTHROPIC_API_KEY" ]; then
        API_KEY_HASH=$(printf '%s' "$ANTHROPIC_API_KEY" | sha256sum | cut -c1-20)
        jq --arg h "$API_KEY_HASH" '
            .customApiKeyResponses = (.customApiKeyResponses // {approved: [], rejected: []})
            | .customApiKeyResponses.approved = (((.customApiKeyResponses.approved // []) + [$h]) | unique)
            | .customApiKeyResponses.rejected = (.customApiKeyResponses.rejected // [])
        ' "$CLAUDE_JSON" > "$tmp" && mv "$tmp" "$CLAUDE_JSON"
    fi

    # 2) Trust /workspace and /workspace/kernel so the trust dialog never fires.
    jq '
        .projects = (.projects // {})
        | .projects["/workspace"] = ((.projects["/workspace"] // {}) + {
            allowedTools: ((.projects["/workspace"].allowedTools) // []),
            mcpContextUris: ((.projects["/workspace"].mcpContextUris) // []),
            mcpServers: ((.projects["/workspace"].mcpServers) // {}),
            enabledMcpjsonServers: ((.projects["/workspace"].enabledMcpjsonServers) // []),
            disabledMcpjsonServers: ((.projects["/workspace"].disabledMcpjsonServers) // []),
            hasTrustDialogAccepted: true
          })
        | .projects["/workspace/kernel"] = ((.projects["/workspace/kernel"] // {}) + {
            allowedTools: ((.projects["/workspace/kernel"].allowedTools) // []),
            mcpContextUris: ((.projects["/workspace/kernel"].mcpContextUris) // []),
            mcpServers: ((.projects["/workspace/kernel"].mcpServers) // {}),
            enabledMcpjsonServers: ((.projects["/workspace/kernel"].enabledMcpjsonServers) // []),
            disabledMcpjsonServers: ((.projects["/workspace/kernel"].disabledMcpjsonServers) // []),
            hasTrustDialogAccepted: true
          })
        | .projects["/app"] = ((.projects["/app"] // {}) + {
            allowedTools: ((.projects["/app"].allowedTools) // []),
            mcpContextUris: ((.projects["/app"].mcpContextUris) // []),
            mcpServers: ((.projects["/app"].mcpServers) // {}),
            enabledMcpjsonServers: ((.projects["/app"].enabledMcpjsonServers) // []),
            disabledMcpjsonServers: ((.projects["/app"].disabledMcpjsonServers) // []),
            hasTrustDialogAccepted: true
          })
    ' "$CLAUDE_JSON" > "$tmp" && mv "$tmp" "$CLAUDE_JSON"

    # 3) Mark onboarding complete against the currently installed CLI version
    #    so a version bump inside the image doesn't re-trigger the wizard.
    CLAUDE_VERSION=$(claude --version 2>/dev/null | awk '{print $1}')
    if [ -n "$CLAUDE_VERSION" ]; then
        jq --arg v "$CLAUDE_VERSION" '
            .hasCompletedOnboarding = true
            | .lastOnboardingVersion = $v
        ' "$CLAUDE_JSON" > "$tmp" && mv "$tmp" "$CLAUDE_JSON"
    fi

    rm -f "$tmp"
fi

# Ensure state directory is writable
mkdir -p "${KERNEL_SCAN_STATE_ROOT:-/var/lib/secflow-kernel-scan}" 2>/dev/null || true

# Backward-compatible fallback for old deployments that mounted Android tool
# archives. New images download and install these tools during docker build.
if [ ! -x /opt/android-tools/adb ] && [ -f /mnt/archives/platform-tools.zip ]; then
    echo "[entrypoint] Extracting platform-tools ..."
    unzip -qo /mnt/archives/platform-tools.zip -d /tmp/pt
    cp /tmp/pt/platform-tools/adb /opt/android-tools/adb
    cp /tmp/pt/platform-tools/fastboot /opt/android-tools/fastboot
    chmod +x /opt/android-tools/adb /opt/android-tools/fastboot
    rm -rf /tmp/pt
    echo "[entrypoint] adb + fastboot ready"
fi

if [ ! -d /opt/android-ndk/toolchains ] && [ -f /mnt/archives/android-ndk.zip ]; then
    echo "[entrypoint] Extracting Android NDK (this may take a moment) ..."
    unzip -qo /mnt/archives/android-ndk.zip -d /tmp/ndk
    # NDK zip extracts to android-ndk-rXX/ — move contents to /opt/android-ndk
    mv /tmp/ndk/android-ndk-*/* /opt/android-ndk/ 2>/dev/null || mv /tmp/ndk/*/* /opt/android-ndk/ 2>/dev/null || true
    rm -rf /tmp/ndk
    echo "[entrypoint] NDK ready ($(ls /opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android*-clang 2>/dev/null | head -1 || echo 'clang not found'))"
fi

exec "$@"
